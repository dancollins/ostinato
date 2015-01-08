/*
Copyright (C) 2014 Srivats P.

This file is part of "Ostinato"

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

#include "dpdkport.h"

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

static struct rte_eth_conf eth_conf; // FIXME: move to DpdkPort?
const quint64 kMaxValue64 = ULLONG_MAX;

int DpdkPort::baseId_ = -1;
QList<DpdkPort*> DpdkPort::allPorts_;
DpdkPort::StatsMonitor *DpdkPort::monitor_;
#ifdef DBG_MBUF_POOL
struct rte_mempool *DpdkPort::mbufPool2_ = NULL;
#endif

DpdkPort::DpdkPort(int id, const char *device, struct rte_mempool *mbufPool)
    : AbstractPort(id, device), mbufPool_(mbufPool)
{
    int ret;
    struct rte_eth_dev_info devInfo;

    Q_ASSERT(baseId_ >= 0);

#ifdef DBG_MBUF_POOL
    mbufPool2_ = mbufPool;
#endif

    // FIXME: this derivation of dpdkPortId_ won't work if one of the previous
    // ports wasn't created for some reason
    dpdkPortId_ = id - baseId_;

    transmitLcoreId_ = -1;

    rte_eth_dev_info_get(dpdkPortId_, &devInfo);

    // FIXME: pass by reference?
    initRxQueueConfig(&devInfo.pci_dev->id);
    initTxQueueConfig(&devInfo.pci_dev->id);

    ret = rte_eth_dev_configure(dpdkPortId_, 
                                1, // # of rx queues
                                1, // # of tx queues
                                &eth_conf);
    if (ret < 0) {
        qWarning("Unable to configure dpdk port %d. err = %d", id, ret);
        goto _error_exit;
    }

    ret = rte_eth_tx_queue_setup(dpdkPortId_,
                                 0,  // queue #
                                 1024, // # of descriptors in ring. FIXME: This should be user-configurable
                                 rte_eth_dev_socket_id(dpdkPortId_),
                                 &txConf_);
    if (ret < 0) {
        qWarning("Unable to configure TxQ for port %d. err = %d", id, ret);
        goto _error_exit;
    }

    ret = rte_eth_rx_queue_setup(dpdkPortId_, 
                                 0,  // queue #
                                 128, // # of descriptors in ring. FIXME: This should be user-configurable
                                 rte_eth_dev_socket_id(dpdkPortId_),
                                 &rxConf_,
                                 mbufPool_);
    if (ret < 0) {
        qWarning("Unable to configure RxQ for port %d. err = %d", id, ret);
        goto _error_exit;
    }

    ret = rte_eth_dev_start(dpdkPortId_);
    if (ret < 0) {
        qWarning("Unable to start port %d. err = %d", id, ret);
        goto _error_exit;
    }

    rte_eth_promiscuous_enable(dpdkPortId_);

    if (!monitor_)
        monitor_ = new StatsMonitor();

    allPorts_.append(this);
    return;

_error_exit:
    isUsable_ = false;
}

DpdkPort::~DpdkPort()
{
    qDebug("In %s", __FUNCTION__);

    if (monitor_->isRunning())
    {
        monitor_->stop();
        monitor_->wait();
    }
}


void DpdkPort::init()
{
    if (!monitor_->isRunning())
        monitor_->start();
}

int DpdkPort::setBaseId(int baseId)
{
    baseId_ = baseId;
    return 0;
}

void DpdkPort::setTransmitLcoreId(unsigned lcoreId)
{
    transmitLcoreId_ = int(lcoreId);
}

void DpdkPort::initRxQueueConfig(const struct rte_pci_id *pciId)
{
    memset(&rxConf_, 0, sizeof(rxConf_));

    switch (pciId->device_id) {
#if 0
    case FIXME:
        rxConf_.rx_thresh.pthresh = 8;
        rxConf_.rx_thresh.hthresh = 8;
        rxConf_.rx_thresh.wthresh = 4;
        break;
#endif
    default:
        break;
    }

}

void DpdkPort::initTxQueueConfig(const struct rte_pci_id *pciId)
{
    memset(&txConf_, 0, sizeof(txConf_));

    switch (pciId->device_id) {
#if 0
    case FIXME:
        txConf_.tx_thresh.pthresh = 36;
        txConf_.tx_thresh.hthresh = 0;
        txConf_.tx_thresh.wthresh = 0;
        txConf_.tx_free_thresh = 0;
        txConf_.tx_rs_thresh = 0;
        txConf_.txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS;
        break;
#endif
    default:
        txConf_.tx_thresh.pthresh = 32;
        txConf_.tx_free_thresh = 32;
        break;
    }
}

bool DpdkPort::hasExclusiveControl()
{
    return false;
}

bool DpdkPort::setExclusiveControl(bool /*exclusive*/)
{
    return false;
}


void DpdkPort::clearPacketList()
{
    for (uint i = 0; i < packetList_.size; i++) {
        struct rte_mbuf *mbuf = packetList_.packets[i].mbuf;
        qDebug("refcnt = %u", rte_mbuf_refcnt_read(mbuf));
        rte_pktmbuf_free(mbuf);
    }
    rte_free(packetList_.packets);
    rte_free(packetList_.packetSet);
    packetList_.reset();
}

void DpdkPort::setPacketListSize(quint64 size)
{
    Q_ASSERT(packetList_.packets == NULL);
    packetList_.size = 0;
    packetList_.maxSize = size;

    if (size == 0)
        return;

    packetList_.packets = (DpdkPacket*) rte_calloc("pktList", size, 
                                                    sizeof(DpdkPacket), 64);
    if (!packetList_.packets)
        qWarning("failed to alloc packetList");

    // syncTransmit() may access max of 1 packetSet beyond the last one, so 
    // we play safe and allocate an extra one
    packetList_.packetSet = (DpdkPacketSet*) rte_calloc("pktSet", 
            activeStreamCount()+1, sizeof(DpdkPacketSet), 64);

    if (!packetList_.packetSet)
        qWarning("failed to alloc packetSet");

    packetList_.packetSet[0].startOfs = 0;
    packetList_.packetSet[0].endOfs = size - 1;
    packetList_.packetSet[0].loopCount = 1;
    packetList_.packetSet[0].repeatDelayUsec = 0;
    // TODO: return sucess/fail result from function
}

void DpdkPort::loopNextPacketSet(qint64 size, qint64 repeats,
                               long repeatDelaySec, long repeatDelayNsec)
{
    DpdkPacketSet *set = &(packetList_.packetSet[packetList_.setSize]);
    set->startOfs = packetList_.size;
    set->endOfs = set->startOfs + size - 1;
    set->loopCount = repeats;
    set->repeatDelayUsec = quint64(repeatDelaySec)*1e6 
                            + quint64(repeatDelayNsec)/1e3;

    qDebug("%s: [%llu] (%llu - %llu)x%llu delay = %llu usec", __FUNCTION__,
            packetList_.setSize, set->startOfs, set->endOfs, 
            set->loopCount, set->repeatDelayUsec);

    packetList_.setSize++;

    if (set->repeatDelayUsec)
        packetList_.topSpeedTransmit = false;
}

bool DpdkPort::appendToPacketList(long sec, long nsec, const uchar *packet, 
                                int length)
{
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbufPool_);
    int len;
    char *pktData;

    if (!mbuf)
        return false;

#if 0
    // Maximize buffer utilization by removing the headroom
    rte_pktmbuf_prepend(mbuf, rte_pktmbuf_headroom(mbuf));
#endif

    // Trucate packet data if our mbuf is not big enough
    // TODO: use segments!
    len = rte_pktmbuf_tailroom(mbuf);
    if (length > len)
       length = len; 

    pktData = rte_pktmbuf_append(mbuf, length);
    if (!pktData) {
        qDebug("not enough tailroom in mbuf");
        rte_pktmbuf_free(mbuf);
        return false;
    }

    rte_memcpy(pktData, packet, length);
    packetList_.packets[packetList_.size].mbuf = mbuf;
    packetList_.packets[packetList_.size].tsSec = sec;
    packetList_.packets[packetList_.size].tsNsec = nsec;
    packetList_.size++;

    //rte_pktmbuf_dump(mbuf, 188);

    if (packetList_.loopDelaySec || packetList_.loopDelayNsec)
        packetList_.topSpeedTransmit = false;

    return true;
}

void DpdkPort::setPacketListLoopMode(bool loop, 
                                   quint64 secDelay, quint64 nsecDelay)
{
    packetList_.loop = loop;
    packetList_.loopDelaySec = secDelay;
    packetList_.loopDelayNsec = nsecDelay;
}

void DpdkPort::startTransmit()
{
    int ret;
    rte_lcore_state_t state;

    if (transmitLcoreId_ < 0) {
        qWarning("Port %d.%s doesn't have a lcore to transmit", id(), name());
        return;
    }

    state = rte_eal_get_lcore_state(transmitLcoreId_);

    Q_ASSERT(state != RUNNING);
	/* If assertions are disabled, we need to handle the error. In this case,
	 * if the port is already running, we don't need to start it again. */
	if (state == RUNNING)
		return;

    if (state == FINISHED)
        rte_eal_wait_lcore(transmitLcoreId_);

    txInfo_.portId = dpdkPortId_;
    txInfo_.stopTx = false;
    txInfo_.pool = mbufPool_;
    txInfo_.list = &packetList_;
    ret = rte_eal_remote_launch(DpdkPort::syncTransmit, &txInfo_, 
                transmitLcoreId_);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to launch transmit\n");
}

void DpdkPort::stopTransmit()
{
    txInfo_.stopTx = true;
    rte_eal_wait_lcore(transmitLcoreId_);
}

bool DpdkPort::isTransmitOn()
{
    rte_lcore_state_t state;

    if (transmitLcoreId_ < 0)
        return false;
   
    state = rte_eal_get_lcore_state(transmitLcoreId_);

    return (state == RUNNING);
}


void DpdkPort::startCapture()
{
}

void DpdkPort::stopCapture()
{
}

bool DpdkPort::isCaptureOn()
{
    return false;
}

QIODevice* DpdkPort::captureData()
{
    return NULL;
}

DpdkPort::StatsMonitor::StatsMonitor() 
{
    portCount_ = rte_eth_dev_count();
    stop_ = false;
}

DpdkPort::StatsMonitor::~StatsMonitor() 
{
}


void DpdkPort::StatsMonitor::stop()
{
    stop_ = true;
}

void DpdkPort::StatsMonitor::run() 
{
    QList<PortStats*> portStats;
    QList<OstProto::LinkState*> linkState;
    int i;

    //
    // Populate the port stats/link lists
    //
    for (i = 0; i < portCount_; i++) {
        portStats.insert(i, &(allPorts_.at(i)->stats_));
        linkState.insert(i, &(allPorts_.at(i)->linkState_));
    }

    // FIXME: portStats/linkState QLists may have holes in them if some
    // port create/init failed

    //
    // We are all set - Let's start polling for stats!
    //
    while (!stop_)
    {
        for (i = 0; i < portCount_; i++) {
            struct rte_eth_stats rteStats;
            struct rte_eth_link rteLink;
            AbstractPort::PortStats *stats = portStats[i];
            OstProto::LinkState *state = linkState[i];

            rte_eth_stats_get(i, &rteStats);
            if (!stats)
                continue;

            stats->rxPps = 
                ((rteStats.ipackets >= stats->rxPkts) ?
                 rteStats.ipackets - stats->rxPkts :
                 rteStats.ipackets + (kMaxValue64 
                     - stats->rxPkts))
                / kRefreshFreq_;
            stats->rxBps = 
                ((rteStats.ibytes >= stats->rxBytes) ?
                 rteStats.ibytes - stats->rxBytes :
                 rteStats.ibytes + (kMaxValue64 
                     - stats->rxBytes))
                / kRefreshFreq_;
            stats->rxPkts  = rteStats.ipackets;
            stats->rxBytes = rteStats.ibytes;

            stats->txPps = 
                ((rteStats.opackets >= stats->txPkts) ?
                 rteStats.opackets - stats->txPkts :
                 rteStats.opackets + (kMaxValue64 
                     - stats->txPkts))
                / kRefreshFreq_;
            stats->txBps = 
                ((rteStats.obytes >= stats->txBytes) ?
                 rteStats.obytes - stats->txBytes :
                 rteStats.obytes + (kMaxValue64 
                     - stats->txBytes))
                / kRefreshFreq_;
            stats->txPkts  = rteStats.opackets;
            stats->txBytes = rteStats.obytes;

            // TODO: export detailed error stats
            stats->rxDrops = rteStats.rx_nombuf; 
            stats->rxErrors = rteStats.ierrors;

            // TODO: export rteStats.oerrors

            Q_ASSERT(state);

            // TODO: investigate if _nowait() is costly
            rte_eth_link_get_nowait(i, &rteLink);
            *state = rteLink.link_status ?
                OstProto::LinkStateUp : OstProto::LinkStateDown;
        }

#ifdef DBG_MBUF_POOL
        portStats[0]->rxFifoErrors = rte_mempool_count(mbufPool2_);
#endif

        QThread::sleep(kRefreshFreq_);
    }

    portStats.clear();
    linkState.clear();
}

/**
 * Used to ge the next packet in the sequence.
 *
 * Passing a packet list will reset the internal state. Subsequent calls
 * should pass NULL.
 *
 * @param list: PacketList describing loop behaviour and holding packets
 * @return The next packet in the sequence. If there are no more packets,
 *         this will return null.
 */
DpdkPort::DpdkPacket *DpdkPort::get_next_packet
(DpdkPort::DpdkPacketList *packet_list) {
	static quint64 pkt_i, loop_i;
	static DpdkPacketList *list;

	DpdkPacket *packet;

	/* If packet list is specified, reset the static variables */
	if (packet_list) {
		list = packet_list;
		pkt_i = 0;
		loop_i = list->packetSet->loopCount;
	}

	/* If we've returned all of the packets, we're done */
	if (pkt_i == list->size)
		return NULL;

	/* Get the next packet */
	packet = &(list->packets[pkt_i++]);

	/* Handle the loop counter */
	if (pkt_i > list->packetSet->endOfs) {
		if (loop_i > 1) {
			loop_i--;
			pkt_i = list->packetSet->startOfs;
		}
	}

	return packet;
}

int DpdkPort::syncTransmit(void *arg) {
	TxInfo *txInfo = (TxInfo*)arg;
	DpdkPacket *packets = txInfo->list->packets;

	int ret;
	quint64 i;

	/* Create memory to store either all of the packets, or the maximum
	 * burst size */
	struct rte_mbuf *pkt_burst[MAX_PKT_BURST];
	int burst_idx = 0;

	/* Calculate the average size and rate for the packets so we can rate
	 * limit them */
	quint64 avg_size = packets->mbuf->buf_len;
	quint64 avg_delay = 0;
	quint64 mbits = 0;
	DpdkPacket *p, *old_p;
	qDebug("%s: Averaging %llu packets for size and rate", __func__,
		   txInfo->list->size);
	for (i = 1; i < txInfo->list->size; i++) {
		p = &packets[i];
		old_p = &packets[i-1];

		/* Need to add FCS, but not preamble */
		avg_size += rte_pktmbuf_pkt_len(p->mbuf) + 4;
		avg_size /= 2;

		avg_delay += ((p->tsSec * 1E9) + p->tsNsec) -
			((old_p->tsSec * 1E9) + old_p->tsNsec);
		/* Ensure we start the rolling average on the second iteration of
		 * this loop */
		if (i > 1)
			avg_delay /= 2;
	}

	/* Calculate Mbits
	 * bits/s = (8 * avg_size) / (avg_delay * 1E-9)
     * Mbits/s = bits/s / 1E6
     *         = [(8 * avg_size) / (avg_delay * 1E-9)] * 1/1E6
	 *         = (8 * avg_size) / (avg_delay * 1E-3)
	 */
	mbits = (8 * avg_size) / (avg_delay * 1E-3);

	qDebug("%s: Avg size: %llu Avg delay: %llu Mbits/s: %llu", __func__,
		   avg_size, avg_delay, mbits);

	/* Rate limit the connection */
	/* TODO: Handle error case */
	ret = rte_eth_set_queue_rate_limit(txInfo->portId, 0, mbits);
	qDebug("%s: queue rate ret: %d", __func__, ret);

	qDebug("%s: sof: %llu eof: %llu loopCount: %llu size: %llu", __func__,
		   txInfo->list->packetSet->startOfs,
		   txInfo->list->packetSet->endOfs,
		   txInfo->list->packetSet->loopCount,
		   txInfo->list->size);

	/* Send the data */
	p = get_next_packet(txInfo->list);
	while (!txInfo->stopTx) {
		/* Fill the burst buffer as much as possible */
		burst_idx = 0;
		while (burst_idx <= MAX_PKT_BURST) {
			/* Tell DPDK not to free this after sending it, as we need it */
			rte_mbuf_refcnt_update(p->mbuf, 1);

			pkt_burst[burst_idx++] = p->mbuf;
			p = get_next_packet(NULL);

			/* Early exit if we run out of packets */
			if (p == NULL)
				break;
		}

		/* Send the burst of packets */
		int nb_tx = 0;
		while (burst_idx-nb_tx > 0) {
			nb_tx += rte_eth_tx_burst(txInfo->portId, 0, &pkt_burst[nb_tx],
									  burst_idx-nb_tx);
		}

		/* Decide if we need to exit or restart the packet getter */
		if (p == NULL) {
			if (!txInfo->list->loop)
				break;

			p = get_next_packet(txInfo->list);
		}
	}

	qDebug("%s: sent %llu packets", __func__, sent);
	qDebug("%s: Finished syncTransmit", __func__);

	return 0;
}

int DpdkPort::topSpeedTransmit(void *arg)
{
    TxInfo *txInfo = (TxInfo*)arg;

    while (!txInfo->stopTx) {
        struct rte_mbuf *mbuf = rte_pktmbuf_alloc(txInfo->pool);
        if (mbuf) {
            rte_pktmbuf_append(mbuf, 64);
            rte_eth_tx_burst(txInfo->portId, 0, &mbuf, 1);
        }
    }

    return 0;
}
