/*
 * Copyright (c) 2016-2017 Hisilicon Limited.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "hns_roce_u.h"
#include "hns_roce_u_db.h"
#include "hns_roce_u_hw_v2.h"

#define HR_IBV_OPC_MAP(ib_key, hr_key) \
		[IBV_WR_ ## ib_key] = HNS_ROCE_WQE_OP_ ## hr_key

static const uint32_t hns_roce_opcode[] = {
	HR_IBV_OPC_MAP(RDMA_WRITE,		RDMA_WRITE),
	HR_IBV_OPC_MAP(RDMA_WRITE_WITH_IMM,	RDMA_WRITE_WITH_IMM),
	HR_IBV_OPC_MAP(SEND,			SEND),
	HR_IBV_OPC_MAP(SEND_WITH_IMM,		SEND_WITH_IMM),
	HR_IBV_OPC_MAP(RDMA_READ,		RDMA_READ),
	HR_IBV_OPC_MAP(ATOMIC_CMP_AND_SWP,	ATOMIC_COM_AND_SWAP),
	HR_IBV_OPC_MAP(ATOMIC_FETCH_AND_ADD,	ATOMIC_FETCH_AND_ADD),
	HR_IBV_OPC_MAP(LOCAL_INV,		LOCAL_INV),
	HR_IBV_OPC_MAP(BIND_MW,			BIND_MW_TYPE),
	HR_IBV_OPC_MAP(SEND_WITH_INV,		SEND_WITH_INV),
};

static inline uint32_t to_hr_opcode(enum ibv_wr_opcode ibv_opcode)
{
	if (ibv_opcode >= ARRAY_SIZE(hns_roce_opcode))
		return HNS_ROCE_WQE_OP_MASK;

	return hns_roce_opcode[ibv_opcode];
}

static const unsigned int hns_roce_mtu[] = {
	[IBV_MTU_256] = 256,
	[IBV_MTU_512] = 512,
	[IBV_MTU_1024] = 1024,
	[IBV_MTU_2048] = 2048,
	[IBV_MTU_4096] = 4096,
};

static inline unsigned int mtu_enum_to_int(enum ibv_mtu mtu)
{
	return hns_roce_mtu[mtu];
}

static void *get_send_sge_ex(struct hns_roce_qp *qp, unsigned int n);

static inline void set_data_seg_v2(struct hns_roce_v2_wqe_data_seg *dseg,
				   struct ibv_sge *sg)
{
	dseg->lkey = htole32(sg->lkey);
	dseg->addr = htole64(sg->addr);
	dseg->len = htole32(sg->length);
}

/* Fill an ending sge to make hw stop reading the remaining sges in wqe */
static inline void set_ending_data_seg(struct hns_roce_v2_wqe_data_seg *dseg)
{
	dseg->lkey = htole32(0x0);
	dseg->addr = 0;
	dseg->len = htole32(INVALID_SGE_LENGTH);
}

static void set_extend_atomic_seg(struct hns_roce_qp *qp, unsigned int sge_cnt,
				  struct hns_roce_sge_info *sge_info, void *buf)
{
	unsigned int sge_mask = qp->ex_sge.sge_cnt - 1;
	unsigned int i;

	for (i = 0; i < sge_cnt; i++, sge_info->start_idx++)
		memcpy(get_send_sge_ex(qp, sge_info->start_idx & sge_mask),
		       buf + i * HNS_ROCE_SGE_SIZE, HNS_ROCE_SGE_SIZE);
}

static int set_atomic_seg(struct hns_roce_qp *qp, struct ibv_send_wr *wr,
			  void *dseg, struct hns_roce_sge_info *sge_info)
{
	struct hns_roce_wqe_atomic_seg *aseg = dseg;
	unsigned int data_len = sge_info->total_len;
	uint8_t tmp[ATOMIC_DATA_LEN_MAX] = {};
	void *buf[ATOMIC_BUF_NUM_MAX];
	unsigned int buf_sge_num;

	if (is_std_atomic(data_len)) {
		if (wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
			aseg->fetchadd_swap_data = htole64(wr->wr.atomic.swap);
			aseg->cmp_data = htole64(wr->wr.atomic.compare_add);
		} else {
			aseg->fetchadd_swap_data =
				htole64(wr->wr.atomic.compare_add);
			aseg->cmp_data = 0;
		}

		return 0;
	}

	if (!is_ext_atomic(data_len))
		return -EINVAL;

	buf_sge_num = data_len >> HNS_ROCE_SGE_SHIFT;
	aseg->fetchadd_swap_data = 0;
	aseg->cmp_data = 0;

	/* both ext CAS and ext FAA need 2 bufs */
	if ((buf_sge_num << 1) + HNS_ROCE_SGE_IN_WQE > qp->sq.max_gs)
		return -EINVAL;

	if (wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
		buf[0] = (void *)(uintptr_t)wr->wr.atomic.swap;
		buf[1] = (void *)(uintptr_t)wr->wr.atomic.compare_add;
	} else {
		buf[0] = (void *)(uintptr_t)wr->wr.atomic.compare_add;
		buf[1] = (void *)(uintptr_t)tmp; /* HW needs all 0 SGEs */
	}

	if (!buf[0] || !buf[1])
		return -EINVAL;

	set_extend_atomic_seg(qp, buf_sge_num, sge_info, buf[0]);
	set_extend_atomic_seg(qp, buf_sge_num, sge_info, buf[1]);

	return 0;
}

static void handle_error_cqe(struct hns_roce_v2_cqe *cqe, struct ibv_wc *wc,
			     uint8_t status)
{
	static const struct {
		unsigned int cqe_status;
		enum ibv_wc_status wc_status;
	} map[] = {
		{ HNS_ROCE_V2_CQE_LOCAL_LENGTH_ERR, IBV_WC_LOC_LEN_ERR },
		{ HNS_ROCE_V2_CQE_LOCAL_QP_OP_ERR, IBV_WC_LOC_QP_OP_ERR },
		{ HNS_ROCE_V2_CQE_LOCAL_PROT_ERR, IBV_WC_LOC_PROT_ERR },
		{ HNS_ROCE_V2_CQE_WR_FLUSH_ERR, IBV_WC_WR_FLUSH_ERR },
		{ HNS_ROCE_V2_CQE_MEM_MANAGERENT_OP_ERR, IBV_WC_MW_BIND_ERR },
		{ HNS_ROCE_V2_CQE_BAD_RESP_ERR, IBV_WC_BAD_RESP_ERR },
		{ HNS_ROCE_V2_CQE_LOCAL_ACCESS_ERR, IBV_WC_LOC_ACCESS_ERR },
		{ HNS_ROCE_V2_CQE_REMOTE_INVAL_REQ_ERR, IBV_WC_REM_INV_REQ_ERR },
		{ HNS_ROCE_V2_CQE_REMOTE_ACCESS_ERR, IBV_WC_REM_ACCESS_ERR },
		{ HNS_ROCE_V2_CQE_REMOTE_OP_ERR, IBV_WC_REM_OP_ERR },
		{ HNS_ROCE_V2_CQE_TRANSPORT_RETRY_EXC_ERR, IBV_WC_RETRY_EXC_ERR },
		{ HNS_ROCE_V2_CQE_RNR_RETRY_EXC_ERR, IBV_WC_RNR_RETRY_EXC_ERR },
		{ HNS_ROCE_V2_CQE_REMOTE_ABORTED_ERR, IBV_WC_REM_ABORT_ERR },
		{ HNS_ROCE_V2_CQE_XRC_VIOLATION_ERR, IBV_WC_REM_INV_RD_REQ_ERR },
	};

	int i;

	wc->status = IBV_WC_GENERAL_ERR;
	for (i = 0; i < ARRAY_SIZE(map); i++) {
		if (status == map[i].cqe_status) {
			wc->status = map[i].wc_status;
			break;
		}
	}

	wc->vendor_err = hr_reg_read(cqe, CQE_SUB_STATUS);
}

static struct hns_roce_v2_cqe *get_cqe_v2(struct hns_roce_cq *cq, int entry)
{
	return cq->buf.buf + entry * cq->cqe_size;
}

static void *get_sw_cqe_v2(struct hns_roce_cq *cq, int n)
{
	struct hns_roce_v2_cqe *cqe = get_cqe_v2(cq, n & cq->ibv_cq.cqe);

	return (hr_reg_read(cqe, CQE_OWNER) ^ !!(n & (cq->ibv_cq.cqe + 1))) ?
	       cqe : NULL;
}

static struct hns_roce_v2_cqe *next_cqe_sw_v2(struct hns_roce_cq *cq)
{
	return get_sw_cqe_v2(cq, cq->cons_index);
}

static void *get_recv_wqe_v2(struct hns_roce_qp *qp, unsigned int n)
{
	return qp->buf.buf + qp->rq.offset + (n << qp->rq.wqe_shift);
}

static void *get_send_wqe(struct hns_roce_qp *qp, unsigned int n)
{
	return qp->buf.buf + qp->sq.offset + (n << qp->sq.wqe_shift);
}

static void *get_send_sge_ex(struct hns_roce_qp *qp, unsigned int n)
{
	return qp->buf.buf + qp->ex_sge.offset + (n << qp->ex_sge.sge_shift);
}

static void *get_srq_wqe(struct hns_roce_srq *srq, unsigned int n)
{
	return srq->wqe_buf.buf + (n << srq->wqe_shift);
}

static void *get_idx_buf(struct hns_roce_idx_que *idx_que, unsigned int n)
{
	return idx_que->buf.buf + (n << idx_que->entry_shift);
}

static void hns_roce_free_srq_wqe(struct hns_roce_srq *srq, uint16_t ind)
{
	uint32_t bitmap_num;
	int bit_num;

	pthread_spin_lock(&srq->lock);

	bitmap_num = ind / BIT_CNT_PER_LONG;
	bit_num = ind % BIT_CNT_PER_LONG;
	srq->idx_que.bitmap[bitmap_num] |= (1ULL << bit_num);
	srq->idx_que.tail++;

	pthread_spin_unlock(&srq->lock);
}

static int get_srq_from_cqe(struct hns_roce_v2_cqe *cqe,
			    struct hns_roce_context *ctx,
			    struct hns_roce_qp *hr_qp,
			    struct hns_roce_srq **srq)
{
	uint32_t srqn;

	if (hr_qp->verbs_qp.qp.qp_type == IBV_QPT_XRC_RECV) {
		srqn = hr_reg_read(cqe, CQE_XRC_SRQN);

		*srq = hns_roce_find_srq(ctx, srqn);
		if (!*srq)
			return -EINVAL;
	} else if (hr_qp->verbs_qp.qp.srq) {
		*srq = to_hr_srq(hr_qp->verbs_qp.qp.srq);
	}

	return 0;
}

static int hns_roce_v2_wq_overflow(struct hns_roce_wq *wq, unsigned int nreq,
				   struct hns_roce_cq *cq)
{
	unsigned int cur;

	cur = wq->head - wq->tail;
	if (cur + nreq < wq->max_post)
		return 0;

	pthread_spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	pthread_spin_unlock(&cq->lock);

	return cur + nreq >= wq->max_post;
}

static void hns_roce_update_rq_db(struct hns_roce_context *ctx,
				  unsigned int qpn, unsigned int rq_head)
{
	struct hns_roce_db rq_db = {};

	hr_reg_write(&rq_db, DB_TAG, qpn);
	hr_reg_write(&rq_db, DB_CMD, HNS_ROCE_V2_RQ_DB);
	hr_reg_write(&rq_db, DB_PI, rq_head);

	hns_roce_write64(ctx->uar + ROCEE_VF_DB_CFG0_OFFSET, (__le32 *)&rq_db);
}

static void hns_roce_update_sq_db(struct hns_roce_context *ctx,
				  struct hns_roce_qp *qp)
{
	struct hns_roce_db sq_db = {};

	hr_reg_write(&sq_db, DB_TAG, qp->verbs_qp.qp.qp_num);
	hr_reg_write(&sq_db, DB_CMD, HNS_ROCE_V2_SQ_DB);
	hr_reg_write(&sq_db, DB_PI, qp->sq.head);
	hr_reg_write(&sq_db, DB_SL, qp->sl);

	hns_roce_write64(qp->sq.db_reg, (__le32 *)&sq_db);
}

static void hns_roce_write512(uint64_t *dest, uint64_t *val)
{
	mmio_memcpy_x64(dest, val, sizeof(struct hns_roce_rc_sq_wqe));
}

static void hns_roce_write_dwqe(struct hns_roce_qp *qp, void *wqe)
{
	struct hns_roce_rc_sq_wqe *rc_sq_wqe = wqe;

	/* All kinds of DirectWQE have the same header field layout */
	hr_reg_enable(rc_sq_wqe, RCWQE_FLAG);
	hr_reg_write(rc_sq_wqe, RCWQE_DB_SL_L, qp->sl);
	hr_reg_write(rc_sq_wqe, RCWQE_DB_SL_H, qp->sl >> HNS_ROCE_SL_SHIFT);
	hr_reg_write(rc_sq_wqe, RCWQE_WQE_IDX, qp->sq.head);

	hns_roce_write512(qp->sq.db_reg, wqe);
}

static void update_cq_db(struct hns_roce_context *ctx, struct hns_roce_cq *cq)
{
	struct hns_roce_db cq_db = {};

	hr_reg_write(&cq_db, DB_TAG, cq->cqn);
	hr_reg_write(&cq_db, DB_CMD, HNS_ROCE_V2_CQ_DB_PTR);
	hr_reg_write(&cq_db, DB_CQ_CI, cq->cons_index);
	hr_reg_write(&cq_db, DB_CQ_CMD_SN, 1);

	hns_roce_write64(ctx->uar + ROCEE_VF_DB_CFG0_OFFSET, (__le32 *)&cq_db);
}

static struct hns_roce_qp *hns_roce_v2_find_qp(struct hns_roce_context *ctx,
					       uint32_t qpn)
{
	uint32_t tind = to_hr_qp_table_index(qpn, ctx);

	if (ctx->qp_table[tind].refcnt)
		return ctx->qp_table[tind].table[qpn & ctx->qp_table_mask];
	else
		return NULL;
}

void hns_roce_v2_clear_qp(struct hns_roce_context *ctx, struct hns_roce_qp *qp)
{
	uint32_t qpn = qp->verbs_qp.qp.qp_num;
	uint32_t tind = to_hr_qp_table_index(qpn, ctx);

	pthread_mutex_lock(&ctx->qp_table_mutex);

	if (!--ctx->qp_table[tind].refcnt)
		free(ctx->qp_table[tind].table);
	else if (!--qp->refcnt)
		ctx->qp_table[tind].table[qpn & ctx->qp_table_mask] = NULL;

	pthread_mutex_unlock(&ctx->qp_table_mutex);
}

static int hns_roce_u_v2_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
				   int attr_mask);

static int hns_roce_flush_cqe(struct hns_roce_qp *hr_qp, uint8_t status)
{
	struct ibv_qp_attr attr;
	int attr_mask;

	if (status != HNS_ROCE_V2_CQE_WR_FLUSH_ERR) {
		attr_mask = IBV_QP_STATE;
		attr.qp_state = IBV_QPS_ERR;
		hns_roce_u_v2_modify_qp(&hr_qp->verbs_qp.qp, &attr, attr_mask);

		hr_qp->verbs_qp.qp.state = IBV_QPS_ERR;
	}

	return V2_CQ_OK;
}

static const unsigned int wc_send_op_map[] = {
	[HNS_ROCE_SQ_OP_SEND] = IBV_WC_SEND,
	[HNS_ROCE_SQ_OP_SEND_WITH_INV] = IBV_WC_SEND,
	[HNS_ROCE_SQ_OP_SEND_WITH_IMM] = IBV_WC_SEND,
	[HNS_ROCE_SQ_OP_RDMA_WRITE] = IBV_WC_RDMA_WRITE,
	[HNS_ROCE_SQ_OP_RDMA_WRITE_WITH_IMM] = IBV_WC_RDMA_WRITE,
	[HNS_ROCE_SQ_OP_RDMA_READ] = IBV_WC_RDMA_READ,
	[HNS_ROCE_SQ_OP_ATOMIC_COMP_AND_SWAP] = IBV_WC_COMP_SWAP,
	[HNS_ROCE_SQ_OP_ATOMIC_FETCH_AND_ADD] = IBV_WC_FETCH_ADD,
	[HNS_ROCE_SQ_OP_LOCAL_INV] = IBV_WC_LOCAL_INV,
	[HNS_ROCE_SQ_OP_BIND_MW] = IBV_WC_BIND_MW,
};

static const unsigned int wc_rcv_op_map[] = {
	[HNS_ROCE_RECV_OP_RDMA_WRITE_IMM] = IBV_WC_RECV_RDMA_WITH_IMM,
	[HNS_ROCE_RECV_OP_SEND] = IBV_WC_RECV,
	[HNS_ROCE_RECV_OP_SEND_WITH_IMM] = IBV_WC_RECV,
	[HNS_ROCE_RECV_OP_SEND_WITH_INV] = IBV_WC_RECV,
};

static void get_opcode_for_resp(struct hns_roce_v2_cqe *cqe, struct ibv_wc *wc,
				uint32_t opcode)
{
	switch (opcode) {
	case HNS_ROCE_RECV_OP_SEND:
		wc->wc_flags = 0;
		break;
	case HNS_ROCE_RECV_OP_SEND_WITH_INV:
		wc->wc_flags = IBV_WC_WITH_INV;
		wc->invalidated_rkey = le32toh(cqe->rkey);
		break;
	case HNS_ROCE_RECV_OP_RDMA_WRITE_IMM:
	case HNS_ROCE_RECV_OP_SEND_WITH_IMM:
		wc->wc_flags = IBV_WC_WITH_IMM;
		wc->imm_data = htobe32(le32toh(cqe->immtdata));
		break;
	default:
		wc->status = IBV_WC_GENERAL_ERR;
		return;
	}

	wc->opcode = wc_rcv_op_map[opcode];
}

static int handle_recv_inl_wqe(struct hns_roce_v2_cqe *cqe, struct ibv_wc *wc,
			       struct hns_roce_qp **cur_qp, uint32_t opcode)
{
	if (((*cur_qp)->verbs_qp.qp.qp_type == IBV_QPT_RC) &&
	    (opcode == HNS_ROCE_RECV_OP_SEND ||
	     opcode == HNS_ROCE_RECV_OP_SEND_WITH_IMM ||
	     opcode == HNS_ROCE_RECV_OP_SEND_WITH_INV) &&
	     hr_reg_read(cqe, CQE_RQ_INLINE)) {
		struct hns_roce_rinl_sge *sge_list;
		uint32_t wr_num, wr_cnt, sge_num, data_len;
		uint8_t *wqe_buf;
		uint32_t sge_cnt, size;

		wr_num = hr_reg_read(cqe, CQE_WQE_IDX);
		wr_cnt = wr_num & ((*cur_qp)->rq.wqe_cnt - 1);

		sge_list = (*cur_qp)->rq_rinl_buf.wqe_list[wr_cnt].sg_list;
		sge_num = (*cur_qp)->rq_rinl_buf.wqe_list[wr_cnt].sge_cnt;
		wqe_buf = (uint8_t *)get_recv_wqe_v2(*cur_qp, wr_cnt);

		data_len = wc->byte_len;

		for (sge_cnt = 0; (sge_cnt < sge_num) && (data_len);
		     sge_cnt++) {
			size = sge_list[sge_cnt].len < data_len ?
			       sge_list[sge_cnt].len : data_len;

			memcpy((void *)sge_list[sge_cnt].addr,
				(void *)wqe_buf, size);
			data_len -= size;
			wqe_buf += size;
		}

		if (data_len) {
			wc->status = IBV_WC_LOC_LEN_ERR;
			return V2_CQ_POLL_ERR;
		}
	}

	return V2_CQ_OK;
}

static void parse_for_ud_qp(struct hns_roce_v2_cqe *cqe, struct ibv_wc *wc)
{
	wc->sl = hr_reg_read(cqe, CQE_SL);
	wc->src_qp = hr_reg_read(cqe, CQE_RMT_QPN);
	wc->slid = 0;
	wc->wc_flags |= hr_reg_read(cqe, CQE_GRH) ? IBV_WC_GRH : 0;
	wc->pkey_index = 0;
}

static void parse_cqe_for_srq(struct hns_roce_v2_cqe *cqe, struct ibv_wc *wc,
			      struct hns_roce_srq *srq)
{
	uint32_t wqe_idx;

	wqe_idx = hr_reg_read(cqe, CQE_WQE_IDX);
	wc->wr_id = srq->wrid[wqe_idx & (srq->wqe_cnt - 1)];
	hns_roce_free_srq_wqe(srq, wqe_idx);
}

static int parse_cqe_for_resp(struct hns_roce_v2_cqe *cqe, struct ibv_wc *wc,
			       struct hns_roce_qp *hr_qp, uint8_t opcode)
{
	struct hns_roce_wq *wq;
	int ret;

	wq = &hr_qp->rq;
	wc->wr_id = wq->wrid[wq->tail & (wq->wqe_cnt - 1)];
	++wq->tail;

	if (hr_qp->verbs_qp.qp.qp_type == IBV_QPT_UD)
		parse_for_ud_qp(cqe, wc);

	ret = handle_recv_inl_wqe(cqe, wc, &hr_qp, opcode);
	if (ret) {
		verbs_err(verbs_get_ctx(hr_qp->verbs_qp.qp.context),
			  PFX "failed to handle recv inline wqe!\n");
		return ret;
	}

	return 0;
}

static void parse_cqe_for_req(struct hns_roce_v2_cqe *cqe, struct ibv_wc *wc,
			      struct hns_roce_qp *hr_qp, uint8_t opcode)
{
	struct hns_roce_wq *wq;
	uint32_t wqe_idx;

	wq = &hr_qp->sq;
	/*
	 * in case of signalling, the tail pointer needs to be updated
	 * according to the wqe idx in the current cqe first
	 */
	if (hr_qp->sq_signal_bits) {
		wqe_idx = hr_reg_read(cqe, CQE_WQE_IDX);
		/* get the processed wqes num since last signalling */
		wq->tail += (wqe_idx - wq->tail) & (wq->wqe_cnt - 1);
	}
	/* write the wr_id of wq into the wc */
	wc->wr_id = wq->wrid[wq->tail & (wq->wqe_cnt - 1)];
	++wq->tail;

	switch (opcode) {
	case HNS_ROCE_SQ_OP_SEND:
	case HNS_ROCE_SQ_OP_SEND_WITH_INV:
	case HNS_ROCE_SQ_OP_RDMA_WRITE:
	case HNS_ROCE_SQ_OP_BIND_MW:
		wc->wc_flags = 0;
		break;
	case HNS_ROCE_SQ_OP_SEND_WITH_IMM:
	case HNS_ROCE_SQ_OP_RDMA_WRITE_WITH_IMM:
		wc->wc_flags = IBV_WC_WITH_IMM;
		break;
	case HNS_ROCE_SQ_OP_LOCAL_INV:
		wc->wc_flags = IBV_WC_WITH_INV;
		break;
	case HNS_ROCE_SQ_OP_RDMA_READ:
	case HNS_ROCE_SQ_OP_ATOMIC_COMP_AND_SWAP:
	case HNS_ROCE_SQ_OP_ATOMIC_FETCH_AND_ADD:
		wc->wc_flags = 0;
		wc->byte_len  = le32toh(cqe->byte_cnt);
		break;
	default:
		wc->status = IBV_WC_GENERAL_ERR;
		wc->wc_flags = 0;
		return;
	}

	wc->opcode = wc_send_op_map[opcode];
}

static int hns_roce_v2_poll_one(struct hns_roce_cq *cq,
				struct hns_roce_qp **cur_qp, struct ibv_wc *wc)
{
	struct hns_roce_context *ctx = to_hr_ctx(cq->ibv_cq.context);
	struct hns_roce_srq *srq = NULL;
	struct hns_roce_v2_cqe *cqe;
	uint8_t opcode;
	uint8_t status;
	uint32_t qpn;
	bool is_send;

	cqe = next_cqe_sw_v2(cq);
	if (!cqe)
		return V2_CQ_EMPTY;

	++cq->cons_index;

	udma_from_device_barrier();

	qpn = hr_reg_read(cqe, CQE_LCL_QPN);

	/* if cur qp is null, then could not get the correct qpn */
	if (!*cur_qp || qpn != (*cur_qp)->verbs_qp.qp.qp_num) {
		*cur_qp = hns_roce_v2_find_qp(ctx, qpn);
		if (!*cur_qp)
			return V2_CQ_POLL_ERR;
	}

	status = hr_reg_read(cqe, CQE_STATUS);
	opcode = hr_reg_read(cqe, CQE_OPCODE);
	is_send = hr_reg_read(cqe, CQE_S_R) == CQE_FOR_SQ;
	if (is_send) {
		parse_cqe_for_req(cqe, wc, *cur_qp, opcode);
	} else {
		wc->byte_len = le32toh(cqe->byte_cnt);
		get_opcode_for_resp(cqe, wc, opcode);

		if (get_srq_from_cqe(cqe, ctx, *cur_qp, &srq))
			return V2_CQ_POLL_ERR;

		if (srq) {
			parse_cqe_for_srq(cqe, wc, srq);
		} else {
			if (parse_cqe_for_resp(cqe, wc, *cur_qp, opcode))
				return V2_CQ_POLL_ERR;
		}
	}

	wc->qp_num = qpn;

	/*
	 * once a cqe in error status, the driver needs to help the HW to
	 * generated flushed cqes for all subsequent wqes
	 */
	if (status != HNS_ROCE_V2_CQE_SUCCESS) {
		handle_error_cqe(cqe, wc, status);
		return hns_roce_flush_cqe(*cur_qp, status);
	}

	wc->status = IBV_WC_SUCCESS;

	return V2_CQ_OK;
}

static int hns_roce_u_v2_poll_cq(struct ibv_cq *ibvcq, int ne,
				 struct ibv_wc *wc)
{
	int npolled;
	int err = V2_CQ_OK;
	struct hns_roce_qp *qp = NULL;
	struct hns_roce_cq *cq = to_hr_cq(ibvcq);
	struct hns_roce_context *ctx = to_hr_ctx(ibvcq->context);

	pthread_spin_lock(&cq->lock);

	for (npolled = 0; npolled < ne; ++npolled) {
		err = hns_roce_v2_poll_one(cq, &qp, wc + npolled);
		if (err != V2_CQ_OK)
			break;
	}

	if (npolled || err == V2_CQ_POLL_ERR) {
		if (cq->flags & HNS_ROCE_CQ_FLAG_RECORD_DB)
			*cq->db = cq->cons_index & RECORD_DB_CI_MASK;
		else
			update_cq_db(ctx, cq);
	}

	pthread_spin_unlock(&cq->lock);

	return err == V2_CQ_POLL_ERR ? err : npolled;
}

static int hns_roce_u_v2_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	struct hns_roce_context *ctx = to_hr_ctx(ibvcq->context);
	struct hns_roce_cq *cq = to_hr_cq(ibvcq);
	struct hns_roce_db cq_db = {};
	uint32_t solicited_flag;
	uint32_t ci;

	ci = cq->cons_index & ((cq->cq_depth << 1) - 1);
	solicited_flag = solicited ? HNS_ROCE_V2_CQ_DB_REQ_SOL :
				     HNS_ROCE_V2_CQ_DB_REQ_NEXT;

	hr_reg_write(&cq_db, DB_TAG, cq->cqn);
	hr_reg_write(&cq_db, DB_CMD, HNS_ROCE_V2_CQ_DB_NTR);
	hr_reg_write(&cq_db, DB_CQ_CI, ci);
	hr_reg_write(&cq_db, DB_CQ_CMD_SN, cq->arm_sn);
	hr_reg_write(&cq_db, DB_CQ_NOTIFY, solicited_flag);

	hns_roce_write64(ctx->uar + ROCEE_VF_DB_CFG0_OFFSET, (__le32 *)&cq_db);

	return 0;
}

static int check_qp_send(struct ibv_qp *qp, struct hns_roce_context *ctx)
{
	if (unlikely(qp->qp_type != IBV_QPT_RC &&
		     qp->qp_type != IBV_QPT_UD) &&
		     qp->qp_type != IBV_QPT_XRC_SEND)
		return -EINVAL;

	if (unlikely(qp->state == IBV_QPS_RESET ||
		     qp->state == IBV_QPS_INIT ||
		     qp->state == IBV_QPS_RTR))
		return -EINVAL;

	return 0;
}

static void set_rc_sge(struct hns_roce_v2_wqe_data_seg *dseg,
		       struct hns_roce_qp *qp, struct ibv_send_wr *wr,
		       struct hns_roce_sge_info *sge_info)
{
	uint32_t mask = qp->ex_sge.sge_cnt - 1;
	uint32_t index = sge_info->start_idx;
	struct ibv_sge *sge = wr->sg_list;
	uint32_t len = 0;
	uint32_t cnt = 0;
	int flag;
	int i;

	flag = (wr->send_flags & IBV_SEND_INLINE &&
		wr->opcode != IBV_WR_ATOMIC_FETCH_AND_ADD &&
		wr->opcode != IBV_WR_ATOMIC_CMP_AND_SWP);

	for (i = 0; i < wr->num_sge; i++, sge++) {
		if (unlikely(!sge->length))
			continue;

		len += sge->length;
		cnt++;

		if (flag)
			continue;

		if (cnt <= HNS_ROCE_SGE_IN_WQE) {
			set_data_seg_v2(dseg, sge);
			dseg++;
		} else {
			dseg = get_send_sge_ex(qp, index & mask);
			set_data_seg_v2(dseg, sge);
			index++;
		}
	}

	sge_info->start_idx = index;
	sge_info->valid_num = cnt;
	sge_info->total_len = len;
}

static void set_ud_sge(struct hns_roce_v2_wqe_data_seg *dseg,
		       struct hns_roce_qp *qp, struct ibv_send_wr *wr,
		       struct hns_roce_sge_info *sge_info)
{
	int flag = wr->send_flags & IBV_SEND_INLINE;
	uint32_t mask = qp->ex_sge.sge_cnt - 1;
	uint32_t index = sge_info->start_idx;
	struct ibv_sge *sge = wr->sg_list;
	uint32_t len = 0;
	uint32_t cnt = 0;
	int i;

	for (i = 0; i < wr->num_sge; i++, sge++) {
		if (unlikely(!sge->length))
			continue;

		len += sge->length;
		cnt++;

		if (flag)
			continue;

		/* No inner sge in UD wqe */
		dseg = get_send_sge_ex(qp, index & mask);
		set_data_seg_v2(dseg, sge);
		index++;
	}

	sge_info->start_idx = index;
	sge_info->valid_num = cnt;
	sge_info->total_len = len;
}

static int fill_ext_sge_inl_data(struct hns_roce_qp *qp,
				 const struct ibv_send_wr *wr,
				 struct hns_roce_sge_info *sge_info)
{
	unsigned int sge_sz = sizeof(struct hns_roce_v2_wqe_data_seg);
	void *dseg;
	int i;

	if (sge_info->total_len > qp->sq.max_gs * sge_sz)
		return EINVAL;

	dseg = get_send_sge_ex(qp, sge_info->start_idx);

	for (i = 0; i < wr->num_sge; i++) {
		memcpy(dseg, (void *)(uintptr_t)wr->sg_list[i].addr,
		       wr->sg_list[i].length);
		dseg += wr->sg_list[i].length;
	}

	sge_info->start_idx += DIV_ROUND_UP(sge_info->total_len, sge_sz);

	return 0;
}

static void fill_ud_inn_inl_data(const struct ibv_send_wr *wr,
				 struct hns_roce_ud_sq_wqe *ud_sq_wqe)
{
	uint8_t data[HNS_ROCE_MAX_UD_INL_INN_SZ] = {0};
	uint32_t *loc = (uint32_t *)data;
	uint32_t tmp_data;
	void *tmp = data;
	int i;

	for (i = 0; i < wr->num_sge; i++) {
		memcpy(tmp, (void *)(uintptr_t)wr->sg_list[i].addr,
		       wr->sg_list[i].length);
		tmp += wr->sg_list[i].length;
	}

	hr_reg_write(ud_sq_wqe, UDWQE_INLINE_DATA_15_0, *loc & 0xffff);
	hr_reg_write(ud_sq_wqe, UDWQE_INLINE_DATA_23_16, (*loc >> 16) & 0xff);

	tmp_data = *loc >> 24;
	loc++;
	tmp_data |= ((*loc & 0xffff) << 8);

	hr_reg_write(ud_sq_wqe, UDWQE_INLINE_DATA_47_24, tmp_data);
	hr_reg_write(ud_sq_wqe, UDWQE_INLINE_DATA_63_48, *loc >> 16);
}

static bool check_inl_data_len(struct hns_roce_qp *qp, unsigned int len)
{
	int mtu = mtu_enum_to_int(qp->path_mtu);

	return (len <= qp->max_inline_data && len <= mtu);
}

static int set_ud_inl(struct hns_roce_qp *qp, const struct ibv_send_wr *wr,
		      struct hns_roce_ud_sq_wqe *ud_sq_wqe,
		      struct hns_roce_sge_info *sge_info)
{
	unsigned int sge_idx = sge_info->start_idx;
	int ret;

	if (!check_inl_data_len(qp, sge_info->total_len))
		return -EINVAL;

	if (sge_info->total_len <= HNS_ROCE_MAX_UD_INL_INN_SZ) {
		hr_reg_clear(ud_sq_wqe, UDWQE_INLINE_TYPE);

		fill_ud_inn_inl_data(wr, ud_sq_wqe);
	} else {
		hr_reg_enable(ud_sq_wqe, UDWQE_INLINE_TYPE);

		ret = fill_ext_sge_inl_data(qp, wr, sge_info);
		if (ret)
			return ret;

		sge_info->valid_num = sge_info->start_idx - sge_idx;

		hr_reg_write(ud_sq_wqe, UDWQE_SGE_NUM, sge_info->valid_num);
	}

	return 0;
}

static __le32 get_immtdata(enum ibv_wr_opcode opcode, const struct ibv_send_wr *wr)
{
	switch (opcode) {
	case IBV_WR_SEND_WITH_IMM:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		return htole32(be32toh(wr->imm_data));
	default:
		return 0;
	}
}

static int check_ud_opcode(struct hns_roce_ud_sq_wqe *ud_sq_wqe,
			   const struct ibv_send_wr *wr)
{
	uint32_t ib_op = wr->opcode;

	if (ib_op != IBV_WR_SEND && ib_op != IBV_WR_SEND_WITH_IMM)
		return EINVAL;

	ud_sq_wqe->immtdata = get_immtdata(ib_op, wr);

	hr_reg_write(ud_sq_wqe, UDWQE_OPCODE, to_hr_opcode(ib_op));

	return 0;
}

static int fill_ud_av(struct hns_roce_ud_sq_wqe *ud_sq_wqe,
		      struct hns_roce_ah *ah)
{
	if (unlikely(ah->av.sl > MAX_SERVICE_LEVEL))
		return EINVAL;

	hr_reg_write(ud_sq_wqe, UDWQE_SL, ah->av.sl);
	hr_reg_write(ud_sq_wqe, UDWQE_PD, to_hr_pd(ah->ibv_ah.pd)->pdn);
	hr_reg_write(ud_sq_wqe, UDWQE_TCLASS, ah->av.tclass);
	hr_reg_write(ud_sq_wqe, UDWQE_HOPLIMIT, ah->av.hop_limit);
	hr_reg_write(ud_sq_wqe, UDWQE_FLOW_LABEL, ah->av.flowlabel);
	hr_reg_write(ud_sq_wqe, UDWQE_UDPSPN, ah->av.udp_sport);
	memcpy(ud_sq_wqe->dmac, ah->av.mac, ETH_ALEN);
	ud_sq_wqe->sgid_index = ah->av.gid_index;
	memcpy(ud_sq_wqe->dgid, ah->av.dgid, HNS_ROCE_GID_SIZE);

	return 0;
}

static int fill_ud_data_seg(struct hns_roce_ud_sq_wqe *ud_sq_wqe,
			    struct hns_roce_qp *qp, struct ibv_send_wr *wr,
			    struct hns_roce_sge_info *sge_info)
{
	int ret = 0;

	hr_reg_write(ud_sq_wqe, UDWQE_MSG_START_SGE_IDX,
		     sge_info->start_idx & (qp->ex_sge.sge_cnt - 1));

	set_ud_sge((struct hns_roce_v2_wqe_data_seg *)ud_sq_wqe, qp, wr, sge_info);

	ud_sq_wqe->msg_len = htole32(sge_info->total_len);

	hr_reg_write(ud_sq_wqe, UDWQE_SGE_NUM, sge_info->valid_num);

	if (wr->send_flags & IBV_SEND_INLINE)
		ret = set_ud_inl(qp, wr, ud_sq_wqe, sge_info);

	return ret;
}

static int set_ud_wqe(void *wqe, struct hns_roce_qp *qp, struct ibv_send_wr *wr,
		      unsigned int nreq, struct hns_roce_sge_info *sge_info)
{
	struct hns_roce_ah *ah = to_hr_ah(wr->wr.ud.ah);
	struct hns_roce_ud_sq_wqe *ud_sq_wqe = wqe;
	int ret = 0;

	hr_reg_write_bool(ud_sq_wqe, UDWQE_CQE,
			  !!(wr->send_flags & IBV_SEND_SIGNALED));
	hr_reg_write_bool(ud_sq_wqe, UDWQE_SE,
			  !!(wr->send_flags & IBV_SEND_SOLICITED));
	hr_reg_write_bool(ud_sq_wqe, UDWQE_INLINE,
			  !!(wr->send_flags & IBV_SEND_INLINE));

	ret = check_ud_opcode(ud_sq_wqe, wr);
	if (ret)
		return ret;

	ud_sq_wqe->qkey = htole32(wr->wr.ud.remote_qkey & 0x80000000 ?
				  qp->qkey : wr->wr.ud.remote_qkey);

	hr_reg_write(ud_sq_wqe, UDWQE_DQPN, wr->wr.ud.remote_qpn);

	ret = fill_ud_av(ud_sq_wqe, ah);
	if (ret)
		return ret;

	ret = fill_ud_data_seg(ud_sq_wqe, qp, wr, sge_info);
	if (ret)
		return ret;

	/*
	 * The pipeline can sequentially post all valid WQEs in wq buf,
	 * including those new WQEs waiting for doorbell to update the PI again.
	 * Therefore, the valid bit of WQE MUST be updated after all of fields
	 * and extSGEs have been written into DDR instead of cache.
	 */
	if (qp->flags & HNS_ROCE_QP_CAP_OWNER_DB)
		udma_to_device_barrier();

	hr_reg_write_bool(wqe, RCWQE_OWNER,
			  !((qp->sq.head + nreq) & BIT(qp->sq.shift)));

	return ret;
}

static int set_rc_inl(struct hns_roce_qp *qp, const struct ibv_send_wr *wr,
		      struct hns_roce_rc_sq_wqe *rc_sq_wqe,
		      struct hns_roce_sge_info *sge_info)
{
	unsigned int sge_idx = sge_info->start_idx;
	void *dseg = rc_sq_wqe;
	int ret;
	int i;

	if (wr->opcode == IBV_WR_RDMA_READ)
		return EINVAL;

	if (!check_inl_data_len(qp, sge_info->total_len))
		return EINVAL;

	dseg += sizeof(struct hns_roce_rc_sq_wqe);

	if (sge_info->total_len <= HNS_ROCE_MAX_RC_INL_INN_SZ) {
		hr_reg_clear(rc_sq_wqe, RCWQE_INLINE_TYPE);

		for (i = 0; i < wr->num_sge; i++) {
			memcpy(dseg, (void *)(uintptr_t)(wr->sg_list[i].addr),
			       wr->sg_list[i].length);
			dseg += wr->sg_list[i].length;
		}
	} else {
		hr_reg_enable(rc_sq_wqe, RCWQE_INLINE_TYPE);

		ret = fill_ext_sge_inl_data(qp, wr, sge_info);
		if (ret)
			return ret;

		sge_info->valid_num = sge_info->start_idx - sge_idx;

		hr_reg_write(rc_sq_wqe, RCWQE_SGE_NUM, sge_info->valid_num);
	}

	return 0;
}

static void set_bind_mw_seg(struct hns_roce_rc_sq_wqe *wqe,
			    const struct ibv_send_wr *wr)
{
	unsigned int access = wr->bind_mw.bind_info.mw_access_flags;

	hr_reg_write_bool(wqe, RCWQE_MW_TYPE, wr->bind_mw.mw->type - 1);
	hr_reg_write_bool(wqe, RCWQE_MW_RA_EN,
			  !!(access & IBV_ACCESS_REMOTE_ATOMIC));
	hr_reg_write_bool(wqe, RCWQE_MW_RR_EN,
			  !!(access & IBV_ACCESS_REMOTE_READ));
	hr_reg_write_bool(wqe, RCWQE_MW_RW_EN,
			  !!(access & IBV_ACCESS_REMOTE_WRITE));

	wqe->new_rkey = htole32(wr->bind_mw.rkey);
	wqe->byte_16 = htole32(wr->bind_mw.bind_info.length &
			       HNS_ROCE_ADDRESS_MASK);
	wqe->byte_20 = htole32(wr->bind_mw.bind_info.length >>
			       HNS_ROCE_ADDRESS_SHIFT);
	wqe->rkey = htole32(wr->bind_mw.bind_info.mr->rkey);
	wqe->va = htole64(wr->bind_mw.bind_info.addr);
}

static int check_rc_opcode(struct hns_roce_rc_sq_wqe *wqe,
			   const struct ibv_send_wr *wr)
{
	int ret = 0;

	wqe->immtdata = get_immtdata(wr->opcode, wr);

	switch (wr->opcode) {
	case IBV_WR_RDMA_READ:
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		wqe->va = htole64(wr->wr.rdma.remote_addr);
		wqe->rkey = htole32(wr->wr.rdma.rkey);
		break;
	case IBV_WR_SEND:
	case IBV_WR_SEND_WITH_IMM:
		break;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		wqe->rkey = htole32(wr->wr.atomic.rkey);
		wqe->va = htole64(wr->wr.atomic.remote_addr);
		break;
	case IBV_WR_LOCAL_INV:
		hr_reg_enable(wqe, RCWQE_SO);
		/* fallthrough */
	case IBV_WR_SEND_WITH_INV:
		wqe->inv_key = htole32(wr->invalidate_rkey);
		break;
	case IBV_WR_BIND_MW:
		set_bind_mw_seg(wqe, wr);
		break;
	default:
		ret = EINVAL;
		break;
	}

	hr_reg_write(wqe, RCWQE_OPCODE, to_hr_opcode(wr->opcode));

	return ret;
}

static int set_rc_wqe(void *wqe, struct hns_roce_qp *qp, struct ibv_send_wr *wr,
		      unsigned int nreq, struct hns_roce_sge_info *sge_info)
{
	struct hns_roce_rc_sq_wqe *rc_sq_wqe = wqe;
	struct hns_roce_v2_wqe_data_seg *dseg;
	int ret;

	hr_reg_write_bool(wqe, RCWQE_CQE,
			  !!(wr->send_flags & IBV_SEND_SIGNALED));
	hr_reg_write_bool(wqe, RCWQE_FENCE,
			  !!(wr->send_flags & IBV_SEND_FENCE));
	hr_reg_write_bool(wqe, RCWQE_SE,
			  !!(wr->send_flags & IBV_SEND_SOLICITED));
	hr_reg_write_bool(wqe, RCWQE_INLINE,
			  !!(wr->send_flags & IBV_SEND_INLINE));
	hr_reg_clear(wqe, RCWQE_SO);

	ret = check_rc_opcode(rc_sq_wqe, wr);
	if (ret)
		return ret;

	hr_reg_write(rc_sq_wqe, RCWQE_MSG_START_SGE_IDX,
		     sge_info->start_idx & (qp->ex_sge.sge_cnt - 1));

	if (wr->opcode == IBV_WR_BIND_MW)
		goto wqe_valid;

	wqe += sizeof(struct hns_roce_rc_sq_wqe);
	dseg = wqe;

	set_rc_sge(dseg, qp, wr, sge_info);

	rc_sq_wqe->msg_len = htole32(sge_info->total_len);

	hr_reg_write(rc_sq_wqe, RCWQE_SGE_NUM, sge_info->valid_num);

	if (wr->opcode == IBV_WR_ATOMIC_FETCH_AND_ADD ||
	    wr->opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
		dseg++;
		ret = set_atomic_seg(qp, wr, dseg, sge_info);
	} else if (wr->send_flags & IBV_SEND_INLINE) {
		ret = set_rc_inl(qp, wr, rc_sq_wqe, sge_info);
	}

	if (ret)
		return ret;

wqe_valid:
	/*
	 * The pipeline can sequentially post all valid WQEs into WQ buffer,
	 * including new WQEs waiting for the doorbell to update the PI again.
	 * Therefore, the owner bit of WQE MUST be updated after all fields
	 * and extSGEs have been written into DDR instead of cache.
	 */
	if (qp->flags & HNS_ROCE_QP_CAP_OWNER_DB)
		udma_to_device_barrier();

	hr_reg_write_bool(wqe, RCWQE_OWNER,
			  !((qp->sq.head + nreq) & BIT(qp->sq.shift)));

	return 0;
}

int hns_roce_u_v2_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
			    struct ibv_send_wr **bad_wr)
{
	struct hns_roce_context *ctx = to_hr_ctx(ibvqp->context);
	struct hns_roce_qp *qp = to_hr_qp(ibvqp);
	struct hns_roce_sge_info sge_info = {};
	struct hns_roce_rc_sq_wqe *wqe;
	unsigned int wqe_idx, nreq;
	struct ibv_qp_attr attr;
	int ret;

	ret = check_qp_send(ibvqp, ctx);
	if (unlikely(ret)) {
		*bad_wr = wr;
		return ret;
	}

	pthread_spin_lock(&qp->sq.lock);

	sge_info.start_idx = qp->next_sge; /* start index of extend sge */

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (hns_roce_v2_wq_overflow(&qp->sq, nreq,
					    to_hr_cq(qp->verbs_qp.qp.send_cq))) {
			ret = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge > qp->sq.max_gs) {
			ret = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		wqe_idx = (qp->sq.head + nreq) & (qp->sq.wqe_cnt - 1);
		wqe = get_send_wqe(qp, wqe_idx);
		qp->sq.wrid[wqe_idx] = wr->wr_id;

		switch (ibvqp->qp_type) {
		case IBV_QPT_XRC_SEND:
			hr_reg_write(wqe, RCWQE_XRC_SRQN,
				     wr->qp_type.xrc.remote_srqn);
			SWITCH_FALLTHROUGH;
		case IBV_QPT_RC:
			ret = set_rc_wqe(wqe, qp, wr, nreq, &sge_info);
			break;
		case IBV_QPT_UD:
			ret = set_ud_wqe(wqe, qp, wr, nreq, &sge_info);
			qp->sl = to_hr_ah(wr->wr.ud.ah)->av.sl;
			break;
		default:
			ret = EINVAL;
		}

		if (ret) {
			*bad_wr = wr;
			goto out;
		}
	}

out:
	if (likely(nreq)) {
		qp->sq.head += nreq;
		qp->next_sge = sge_info.start_idx;

		udma_to_device_barrier();

		if (nreq == 1 && (qp->flags & HNS_ROCE_QP_CAP_DIRECT_WQE))
			hns_roce_write_dwqe(qp, wqe);
		else
			hns_roce_update_sq_db(ctx, qp);

		if (qp->flags & HNS_ROCE_QP_CAP_SQ_RECORD_DB)
			*(qp->sdb) = qp->sq.head & 0xffff;
	}

	pthread_spin_unlock(&qp->sq.lock);

	if (ibvqp->state == IBV_QPS_ERR) {
		attr.qp_state = IBV_QPS_ERR;

		hns_roce_u_v2_modify_qp(ibvqp, &attr, IBV_QP_STATE);
	}

	return ret;
}

static int check_qp_recv(struct ibv_qp *qp, struct hns_roce_context *ctx)
{
	if (unlikely(qp->qp_type != IBV_QPT_RC &&
		     qp->qp_type != IBV_QPT_UD))
		return -EINVAL;

	if (qp->state == IBV_QPS_RESET || qp->srq)
		return -EINVAL;

	return 0;
}

static void fill_rq_wqe(struct hns_roce_qp *qp, struct ibv_recv_wr *wr,
			unsigned int wqe_idx)
{
	struct hns_roce_v2_wqe_data_seg *dseg;
	struct hns_roce_rinl_sge *sge_list;
	int i;

	dseg = get_recv_wqe_v2(qp, wqe_idx);
	for (i = 0; i < wr->num_sge; i++) {
		if (!wr->sg_list[i].length)
			continue;
		set_data_seg_v2(dseg, wr->sg_list + i);
		dseg++;
	}

	if (qp->rq.rsv_sge)
		set_ending_data_seg(dseg);

	if (!qp->rq_rinl_buf.wqe_cnt)
		return;

	/* QP support receive inline wqe */
	sge_list = qp->rq_rinl_buf.wqe_list[wqe_idx].sg_list;
	qp->rq_rinl_buf.wqe_list[wqe_idx].sge_cnt = (unsigned int)wr->num_sge;
	for (i = 0; i < wr->num_sge; i++) {
		sge_list[i].addr = (void *)(uintptr_t)wr->sg_list[i].addr;
		sge_list[i].len = wr->sg_list[i].length;
	}
}

static int hns_roce_u_v2_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
				   struct ibv_recv_wr **bad_wr)
{
	struct hns_roce_context *ctx = to_hr_ctx(ibvqp->context);
	struct hns_roce_qp *qp = to_hr_qp(ibvqp);
	unsigned int wqe_idx, nreq, max_sge;
	struct ibv_qp_attr attr;
	int ret;

	ret = check_qp_recv(ibvqp, ctx);
	if (unlikely(ret)) {
		*bad_wr = wr;
		return ret;
	}

	pthread_spin_lock(&qp->rq.lock);

	max_sge = qp->rq.max_gs - qp->rq.rsv_sge;
	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		if (hns_roce_v2_wq_overflow(&qp->rq, nreq,
					    to_hr_cq(qp->verbs_qp.qp.recv_cq))) {
			ret = ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (wr->num_sge > max_sge) {
			ret = EINVAL;
			*bad_wr = wr;
			goto out;
		}

		wqe_idx = (qp->rq.head + nreq) & (qp->rq.wqe_cnt - 1);
		fill_rq_wqe(qp, wr, wqe_idx);
		qp->rq.wrid[wqe_idx] = wr->wr_id;
	}

out:
	if (nreq) {
		qp->rq.head += nreq;

		udma_to_device_barrier();

		if (qp->flags & HNS_ROCE_QP_CAP_RQ_RECORD_DB)
			*qp->rdb = qp->rq.head & 0xffff;
		else
			hns_roce_update_rq_db(ctx, ibvqp->qp_num, qp->rq.head);
	}

	pthread_spin_unlock(&qp->rq.lock);

	if (ibvqp->state == IBV_QPS_ERR) {
		attr.qp_state = IBV_QPS_ERR;
		hns_roce_u_v2_modify_qp(ibvqp, &attr, IBV_QP_STATE);
	}

	return ret;
}

static void __hns_roce_v2_cq_clean(struct hns_roce_cq *cq, uint32_t qpn,
				   struct hns_roce_srq *srq)
{
	int nfreed = 0;
	bool is_recv_cqe;
	uint8_t owner_bit;
	uint16_t wqe_index;
	uint32_t prod_index;
	struct hns_roce_v2_cqe *cqe, *dest;
	struct hns_roce_context *ctx = to_hr_ctx(cq->ibv_cq.context);

	for (prod_index = cq->cons_index; get_sw_cqe_v2(cq, prod_index);
	     ++prod_index)
		if (prod_index > cq->cons_index + cq->ibv_cq.cqe)
			break;

	while ((int) --prod_index - (int) cq->cons_index >= 0) {
		cqe = get_cqe_v2(cq, prod_index & cq->ibv_cq.cqe);
		if (hr_reg_read(cqe, CQE_LCL_QPN) == qpn) {
			is_recv_cqe = hr_reg_read(cqe, CQE_S_R);

			if (srq && is_recv_cqe) {
				wqe_index = hr_reg_read(cqe, CQE_WQE_IDX);
				hns_roce_free_srq_wqe(srq, wqe_index);
			}
			++nfreed;
		} else if (nfreed) {
			dest = get_cqe_v2(cq,
				       (prod_index + nfreed) & cq->ibv_cq.cqe);
			owner_bit = hr_reg_read(dest, CQE_OWNER);
			memcpy(dest, cqe, cq->cqe_size);
			hr_reg_write_bool(dest, CQE_OWNER, owner_bit);
		}
	}

	if (nfreed) {
		cq->cons_index += nfreed;
		udma_to_device_barrier();
		update_cq_db(ctx, cq);
	}
}

static void hns_roce_v2_cq_clean(struct hns_roce_cq *cq, unsigned int qpn,
				 struct hns_roce_srq *srq)
{
	pthread_spin_lock(&cq->lock);
	__hns_roce_v2_cq_clean(cq, qpn, srq);
	pthread_spin_unlock(&cq->lock);
}

static void record_qp_attr(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			   int attr_mask)
{
	struct hns_roce_qp *hr_qp = to_hr_qp(qp);

	if (attr_mask & IBV_QP_PORT)
		hr_qp->port_num = attr->port_num;

	if (attr_mask & IBV_QP_AV)
		hr_qp->sl = attr->ah_attr.sl;

	if (attr_mask & IBV_QP_QKEY)
		hr_qp->qkey = attr->qkey;

	if (qp->qp_type == IBV_QPT_UD)
		hr_qp->path_mtu = IBV_MTU_4096;
	else if (attr_mask & IBV_QP_PATH_MTU)
		hr_qp->path_mtu = attr->path_mtu;
}

static int hns_roce_u_v2_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
				   int attr_mask)
{
	int ret;
	struct ibv_modify_qp cmd;
	struct hns_roce_qp *hr_qp = to_hr_qp(qp);
	bool flag = false; /* modify qp to error */

	if ((attr_mask & IBV_QP_STATE) && (attr->qp_state == IBV_QPS_ERR)) {
		pthread_spin_lock(&hr_qp->sq.lock);
		pthread_spin_lock(&hr_qp->rq.lock);
		flag = true;
	}

	ret = ibv_cmd_modify_qp(qp, attr, attr_mask, &cmd, sizeof(cmd));

	if (flag) {
		pthread_spin_unlock(&hr_qp->rq.lock);
		pthread_spin_unlock(&hr_qp->sq.lock);
	}

	if (ret)
		return ret;

	if (attr_mask & IBV_QP_STATE)
		qp->state = attr->qp_state;

	if ((attr_mask & IBV_QP_STATE) && attr->qp_state == IBV_QPS_RESET) {
		if (qp->recv_cq)
			hns_roce_v2_cq_clean(to_hr_cq(qp->recv_cq), qp->qp_num,
					     qp->srq ? to_hr_srq(qp->srq) :
					     NULL);
		if (qp->send_cq && qp->send_cq != qp->recv_cq)
			hns_roce_v2_cq_clean(to_hr_cq(qp->send_cq), qp->qp_num,
					     NULL);

		hns_roce_init_qp_indices(to_hr_qp(qp));
	}

	record_qp_attr(qp, attr, attr_mask);

	return ret;
}

static void hns_roce_lock_cqs(struct ibv_qp *qp)
{
	struct hns_roce_cq *send_cq = to_hr_cq(qp->send_cq);
	struct hns_roce_cq *recv_cq = to_hr_cq(qp->recv_cq);

	if (send_cq && recv_cq) {
		if (send_cq == recv_cq) {
			pthread_spin_lock(&send_cq->lock);
		} else if (send_cq->cqn < recv_cq->cqn) {
			pthread_spin_lock(&send_cq->lock);
			pthread_spin_lock(&recv_cq->lock);
		} else {
			pthread_spin_lock(&recv_cq->lock);
			pthread_spin_lock(&send_cq->lock);
		}
	} else if (send_cq) {
		pthread_spin_lock(&send_cq->lock);
	} else if (recv_cq) {
		pthread_spin_lock(&recv_cq->lock);
	}
}

static void hns_roce_unlock_cqs(struct ibv_qp *qp)
{
	struct hns_roce_cq *send_cq = to_hr_cq(qp->send_cq);
	struct hns_roce_cq *recv_cq = to_hr_cq(qp->recv_cq);

	if (send_cq && recv_cq) {
		if (send_cq == recv_cq) {
			pthread_spin_unlock(&send_cq->lock);
		} else if (send_cq->cqn < recv_cq->cqn) {
			pthread_spin_unlock(&recv_cq->lock);
			pthread_spin_unlock(&send_cq->lock);
		} else {
			pthread_spin_unlock(&send_cq->lock);
			pthread_spin_unlock(&recv_cq->lock);
		}
	} else if (send_cq) {
		pthread_spin_unlock(&send_cq->lock);
	} else if (recv_cq) {
		pthread_spin_unlock(&recv_cq->lock);
	}
}

static int hns_roce_u_v2_destroy_qp(struct ibv_qp *ibqp)
{
	struct hns_roce_context *ctx = to_hr_ctx(ibqp->context);
	struct hns_roce_qp *qp = to_hr_qp(ibqp);
	int ret;

	ret = ibv_cmd_destroy_qp(ibqp);
	if (ret)
		return ret;

	if (qp->flags & HNS_ROCE_QP_CAP_DIRECT_WQE)
		munmap(qp->dwqe_page, HNS_ROCE_DWQE_PAGE_SIZE);

	hns_roce_v2_clear_qp(ctx, qp);

	hns_roce_lock_cqs(ibqp);

	if (ibqp->recv_cq)
		__hns_roce_v2_cq_clean(to_hr_cq(ibqp->recv_cq), ibqp->qp_num,
				       ibqp->srq ? to_hr_srq(ibqp->srq) : NULL);

	if (ibqp->send_cq && ibqp->send_cq != ibqp->recv_cq)
		__hns_roce_v2_cq_clean(to_hr_cq(ibqp->send_cq), ibqp->qp_num,
				       NULL);

	hns_roce_unlock_cqs(ibqp);

	hns_roce_free_qp_buf(qp, ctx);

	free(qp);

	return ret;
}

static int hns_roce_v2_srqwq_overflow(struct hns_roce_srq *srq)
{
	struct hns_roce_idx_que *idx_que = &srq->idx_que;

	return idx_que->head - idx_que->tail >= srq->wqe_cnt;
}

static int check_post_srq_valid(struct hns_roce_srq *srq,
				struct ibv_recv_wr *wr)
{
	unsigned int max_sge = srq->max_gs - srq->rsv_sge;

	if (hns_roce_v2_srqwq_overflow(srq))
		return -ENOMEM;

	if (wr->num_sge > max_sge)
		return -EINVAL;

	return 0;
}

static int get_wqe_idx(struct hns_roce_srq *srq, unsigned int *wqe_idx)
{
	struct hns_roce_idx_que *idx_que = &srq->idx_que;
	int bit_num;
	int i;

	/* bitmap[i] is set zero if all bits are allocated */
	for (i = 0; i < idx_que->bitmap_cnt && idx_que->bitmap[i] == 0; ++i)
		;
	if (i == idx_que->bitmap_cnt)
		return -ENOMEM;

	bit_num = ffsl(idx_que->bitmap[i]);
	idx_que->bitmap[i] &= ~(1ULL << (bit_num - 1));

	*wqe_idx = i * BIT_CNT_PER_LONG + (bit_num - 1);

	/* If wqe_cnt is less than BIT_CNT_PER_LONG, wqe_idx may be greater
	 * than wqe_cnt.
	 */
	if (*wqe_idx >= srq->wqe_cnt)
		return -ENOMEM;

	return 0;
}

static void fill_srq_wqe(struct hns_roce_srq *srq, unsigned int wqe_idx,
			 struct ibv_recv_wr *wr)
{
	struct hns_roce_v2_wqe_data_seg *dseg;
	int i;

	dseg = get_srq_wqe(srq, wqe_idx);

	for (i = 0; i < wr->num_sge; ++i) {
		dseg[i].len = htole32(wr->sg_list[i].length);
		dseg[i].lkey = htole32(wr->sg_list[i].lkey);
		dseg[i].addr = htole64(wr->sg_list[i].addr);
	}

	/* hw stop reading when identify the last one */
	if (srq->rsv_sge) {
		dseg[i].len = htole32(INVALID_SGE_LENGTH);
		dseg[i].lkey = htole32(0x0);
		dseg[i].addr = 0;
	}
}

static void fill_wqe_idx(struct hns_roce_srq *srq, unsigned int wqe_idx)
{
	struct hns_roce_idx_que *idx_que = &srq->idx_que;
	unsigned int head;
	__le32 *idx_buf;

	head = idx_que->head & (srq->wqe_cnt - 1);

	idx_buf = get_idx_buf(idx_que, head);
	*idx_buf = htole32(wqe_idx);

	idx_que->head++;
}

static void update_srq_db(struct hns_roce_db *db, struct hns_roce_srq *srq)
{
	hr_reg_write(db, DB_TAG, srq->srqn);
	hr_reg_write(db, DB_CMD, HNS_ROCE_V2_SRQ_DB);
	hr_reg_write(db, DB_PI, srq->idx_que.head);
}

static int hns_roce_u_v2_post_srq_recv(struct ibv_srq *ib_srq,
				       struct ibv_recv_wr *wr,
				       struct ibv_recv_wr **bad_wr)
{
	struct hns_roce_context *ctx = to_hr_ctx(ib_srq->context);
	struct hns_roce_srq *srq = to_hr_srq(ib_srq);
	struct hns_roce_db srq_db;
	unsigned int wqe_idx;
	int ret = 0;
	int nreq;

	pthread_spin_lock(&srq->lock);

	for (nreq = 0; wr; ++nreq, wr = wr->next) {
		ret = check_post_srq_valid(srq, wr);
		if (ret) {
			*bad_wr = wr;
			break;
		}

		ret = get_wqe_idx(srq, &wqe_idx);
		if (ret) {
			*bad_wr = wr;
			break;
		}

		fill_srq_wqe(srq, wqe_idx, wr);
		fill_wqe_idx(srq, wqe_idx);

		srq->wrid[wqe_idx] = wr->wr_id;
	}

	if (nreq) {
		/*
		 * Make sure that descriptors are written before
		 * we write doorbell record.
		 */
		udma_to_device_barrier();

		update_srq_db(&srq_db, srq);

		hns_roce_write64(ctx->uar + ROCEE_VF_DB_CFG0_OFFSET,
				 (__le32 *)&srq_db);
	}

	pthread_spin_unlock(&srq->lock);

	return ret;
}

const struct hns_roce_u_hw hns_roce_u_hw_v2 = {
	.hw_version = HNS_ROCE_HW_VER2,
	.hw_ops = {
		.poll_cq = hns_roce_u_v2_poll_cq,
		.req_notify_cq = hns_roce_u_v2_arm_cq,
		.post_send = hns_roce_u_v2_post_send,
		.post_recv = hns_roce_u_v2_post_recv,
		.modify_qp = hns_roce_u_v2_modify_qp,
		.destroy_qp = hns_roce_u_v2_destroy_qp,
		.post_srq_recv = hns_roce_u_v2_post_srq_recv,
	},
};
