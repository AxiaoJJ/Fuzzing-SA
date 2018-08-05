/*
 *  RDMA device: Definitions of Backend Device functions
 *
 * Copyright (C) 2018 Oracle
 * Copyright (C) 2018 Red Hat Inc
 *
 * Authors:
 *     Yuval Shaia <yuval.shaia@oracle.com>
 *     Marcel Apfelbaum <marcel@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef RDMA_BACKEND_H
#define RDMA_BACKEND_H

#include "qapi/error.h"
#include "rdma_rm_defs.h"
#include "rdma_backend_defs.h"

/* Add definition for QP0 and QP1 as there is no userspace enums for them */
enum ibv_special_qp_type {
    IBV_QPT_SMI = 0,
    IBV_QPT_GSI = 1,
};

static inline union ibv_gid *rdma_backend_gid(RdmaBackendDev *dev)
{
    return &dev->gid;
}

static inline uint32_t rdma_backend_qpn(const RdmaBackendQP *qp)
{
    return qp->ibqp ? qp->ibqp->qp_num : 0;
}

static inline uint32_t rdma_backend_mr_lkey(const RdmaBackendMR *mr)
{
    return mr->ibmr ? mr->ibmr->lkey : 0;
}

static inline uint32_t rdma_backend_mr_rkey(const RdmaBackendMR *mr)
{
    return mr->ibmr ? mr->ibmr->rkey : 0;
}

int rdma_backend_init(RdmaBackendDev *backend_dev,
                      RdmaDeviceResources *rdma_dev_res,
                      const char *backend_device_name, uint8_t port_num,
                      uint8_t backend_gid_idx, struct ibv_device_attr *dev_attr,
                      Error **errp);
void rdma_backend_fini(RdmaBackendDev *backend_dev);
void rdma_backend_start(RdmaBackendDev *backend_dev);
void rdma_backend_stop(RdmaBackendDev *backend_dev);
void rdma_backend_register_comp_handler(void (*handler)(int status,
                                        unsigned int vendor_err, void *ctx));
void rdma_backend_unregister_comp_handler(void);

int rdma_backend_query_port(RdmaBackendDev *backend_dev,
                            struct ibv_port_attr *port_attr);
int rdma_backend_create_pd(RdmaBackendDev *backend_dev, RdmaBackendPD *pd);
void rdma_backend_destroy_pd(RdmaBackendPD *pd);

int rdma_backend_create_mr(RdmaBackendMR *mr, RdmaBackendPD *pd, void *addr,
                           size_t length, int access);
void rdma_backend_destroy_mr(RdmaBackendMR *mr);

int rdma_backend_create_cq(RdmaBackendDev *backend_dev, RdmaBackendCQ *cq,
                           int cqe);
void rdma_backend_destroy_cq(RdmaBackendCQ *cq);
void rdma_backend_poll_cq(RdmaDeviceResources *rdma_dev_res, RdmaBackendCQ *cq);

int rdma_backend_create_qp(RdmaBackendQP *qp, uint8_t qp_type,
                           RdmaBackendPD *pd, RdmaBackendCQ *scq,
                           RdmaBackendCQ *rcq, uint32_t max_send_wr,
                           uint32_t max_recv_wr, uint32_t max_send_sge,
                           uint32_t max_recv_sge);
int rdma_backend_qp_state_init(RdmaBackendDev *backend_dev, RdmaBackendQP *qp,
                               uint8_t qp_type, uint32_t qkey);
int rdma_backend_qp_state_rtr(RdmaBackendDev *backend_dev, RdmaBackendQP *qp,
                              uint8_t qp_type, union ibv_gid *dgid,
                              uint32_t dqpn, uint32_t rq_psn, uint32_t qkey,
                              bool use_qkey);
int rdma_backend_qp_state_rts(RdmaBackendQP *qp, uint8_t qp_type,
                              uint32_t sq_psn, uint32_t qkey, bool use_qkey);
int rdma_backend_query_qp(RdmaBackendQP *qp, struct ibv_qp_attr *attr,
                          int attr_mask, struct ibv_qp_init_attr *init_attr);
void rdma_backend_destroy_qp(RdmaBackendQP *qp);

void rdma_backend_post_send(RdmaBackendDev *backend_dev,
                            RdmaBackendQP *qp, uint8_t qp_type,
                            struct ibv_sge *sge, uint32_t num_sge,
                            union ibv_gid *dgid, uint32_t dqpn, uint32_t dqkey,
                            void *ctx);
void rdma_backend_post_recv(RdmaBackendDev *backend_dev,
                            RdmaDeviceResources *rdma_dev_res,
                            RdmaBackendQP *qp, uint8_t qp_type,
                            struct ibv_sge *sge, uint32_t num_sge, void *ctx);

#endif
