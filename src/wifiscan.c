/*
 * wifiscan.c: detects all access points on wlan0 using NL80211 (netlink).
 *
 * only root may submit NL80211_CMD_TRIGGER_SCAN, hence must be run as root
 *
 * Library dependencies:
 *      libnl-3-dev libnl-genl-3-dev
 */

#include <errno.h>
#ifndef __APPLE__
#include <netlink/errno.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <linux/nl80211.h>
#endif
#include <witutil.h>
#include "libwit.h"

static unsigned int chans[MAX_CHANS];

// freq to channel helper
//
// from: http://stackoverflow.com/questions/5485759/android-how-to-determine-a-wifi-channel-number-used-by-wifi-ap-network
static int
convertFrequencyToChannel(int freq) {
    if (freq >= 2412 && freq <= 2484) {
        return (freq - 2412) / 5 + 1;
    } else if (freq >= 5170 && freq <= 5825) {
        return (freq - 5170) / 5 + 34;
    } else {
        return -1;
    }
}

// freq to channel helper
//
// implemented the reverse of above
//
static int
convertChannelToFrequency(int chan)
{
    if (chan <= 14)
        return (2412 + ((chan - 1) * 5));
    else if (chan <= 165)
        return (5170 + ((chan - 34) * 5));
    else
        return 0;
}

// next_least_used_channel
//
// North American (NA) channel list
// 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
// 36, 40, 44, 48, 52, 56, 60, 64,
// 100, 104, 108, 112, 116,
// 132, 136, 140,
// 149, 153, 157, 161, 165,
//
// returns the best channel to use
//
static int
next_least_used_channel(unsigned int ghz, AccessPoint* ap_list)
{
    AccessPoint* ap = ap_list;
    unsigned int best_chan_val = 255;
    unsigned int best_chan = 0;
    unsigned int inc;
    unsigned int i;

    LOG(INFO, "(%d, %p)", ghz, ap_list);
    bzero(chans, MAX_CHANS*sizeof(unsigned int));

    // fill the chans array...
    while (ap != NULL) {
        chans[ap->channel.chan_num]++;
    ap = ap->next;
    }
 
    // check channel list for next best channel...
    for (i = 1, inc = 1; i < MAX_CHANS; i += inc) {

        if (i == 12)    // skip first NA hole
            i = 36;

        if (i == 68)    // skip second NA hole
            i = 100;

        if (i == 120)    // skip third NA hole
            i = 132;

        if (i == 144)    // skip fourth NA hole
            i = 149;

        if (i > 14)    // increment by 4 after 1st 14 channels
            inc = 4;

        if (best_chan_val > chans[i]) {
            if ((ghz == 2 && i < 12) || (ghz == 5 && i > 35)) {
                best_chan_val = chans[i];
                best_chan = i;

                if (best_chan_val == 0)
                    break;
            }
        }
    }

    return best_chan;
}

#ifndef __APPLE__
// parse Netlink Information Element
//
// a work in progress - currently only parses SSID
//
#define IE_HDR              2
#define IE_LEN(__ie)        __ie[1]
#define IE_DATA(__ie, __i)  __ie[2+__i]
#define ELT_LEN(_ie)       (IE_LEN(_ie) + IE_HDR)
static void
parse_bss_info_elements(struct nlattr **bss, AccessPoint* ap)
{
    uint8_t *elt = (uint8_t*)nla_data(*bss);
    int elt_len = nla_len(*bss);
    int i;

    if (ap == NULL) {
        LOG(ERROR, "called with NULL ap");
        return;
    }

    while (elt_len >= IE_HDR && elt_len >= IE_LEN(elt)) {
        // header byte == 0 == SSID
        if (elt[0] == 0) {
            // SSIDs ar 32 bytes max
            if (IE_LEN(elt) >= 0 && IE_LEN(elt) <= 32) {

                for (i = 0; i < IE_LEN(elt); i++) {
                    if (isprint(IE_DATA(elt, i)) &&
                                IE_DATA(elt, i) != ' ' &&
                                IE_DATA(elt, i) != '\\') {
                        ap->ssid[i] = IE_DATA(elt, i);
                    } else if (IE_DATA(elt, i) == ' ' &&
                              (i != 0 && i != IE_LEN(elt) -1)) {
                        ap->ssid[i] = IE_DATA(elt, i);
                    } else {
                        ap->ssid[i] = '*';
                    }
                }
                break;
            }
        }

        elt_len -= ELT_LEN(elt);
        elt += ELT_LEN(elt);
    }
}

// ERROR Callback
//
// returns NL_STOP in all cases
//
static int
error_cb(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
    if (err) {
        if (arg)
            *(int*)arg = err->error;

        LOG(ERROR, "called with %d", err->error);
    } else {
        LOG(ERROR,"called without err!?d");
    }

    return NL_STOP;
}

// NL_CB_FINISH Callback
//
// returns NL_SKIP in all cases
//
static int
finish_cb(struct nl_msg *msg, void *arg)
{
    if (arg)
        *(int*)arg = 0;

    LOG(NOTICE,"called");
    return NL_SKIP;
}

// NL_CB_ACK Callback
//
// returns NL_STOP in all cases
//
static int
ack_cb(struct nl_msg *msg, void *arg)
{
    if (arg)
        *(int*)arg = 0;

    LOG(NOTICE,"called");
    return NL_STOP;
}

// NL_CB_SEQ_CHECK Callback
//
// returns NL_OK in all cases (stubbed)
//
static int
seq_check_cb(struct nl_msg *msg, void *arg)
{
    LOG(NOTICE,"called");
    return NL_OK;
}

// Multicast Callback
//
// returns NL_SKIP in all cases
//
static int
mcast_cb(struct nl_msg *msg, void *arg)
{
    int *mcast_id = arg;
    struct nlattr *mcast_grp;
    struct nlattr *nl_attrs[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gmsg = nlmsg_data(nlmsg_hdr(msg));
    int remain;

    nla_parse(nl_attrs, CTRL_ATTR_MAX,
              genlmsg_attrdata(gmsg, 0), genlmsg_attrlen(gmsg, 0), NULL);

    if (!nl_attrs[CTRL_ATTR_MCAST_GROUPS])
        return NL_SKIP;

    remain = nla_len(nl_attrs[CTRL_ATTR_MCAST_GROUPS]);
    nla_for_each_nested(mcast_grp, nl_attrs[CTRL_ATTR_MCAST_GROUPS], remain) {
        struct nlattr *mcast_grp_attrs[CTRL_ATTR_MCAST_GRP_MAX + 1];

        nla_parse(mcast_grp_attrs, CTRL_ATTR_MCAST_GRP_MAX,
                  nla_data(mcast_grp), nla_len(mcast_grp), NULL);

        // We need a valid group name and ID...
        if (!mcast_grp_attrs[CTRL_ATTR_MCAST_GRP_NAME] ||
            !mcast_grp_attrs[CTRL_ATTR_MCAST_GRP_ID])
            continue;

        // We need the group name to be 'scan'...
        if (strncmp(nla_data(mcast_grp_attrs[CTRL_ATTR_MCAST_GRP_NAME]), "scan",
                    nla_len(mcast_grp_attrs[CTRL_ATTR_MCAST_GRP_NAME])))
            continue;

        // harvest the 'scan' multicast group ID
        *mcast_id = nla_get_u32(mcast_grp_attrs[CTRL_ATTR_MCAST_GRP_ID]);
        break;
    }

    return NL_SKIP;
}

// Scan Request Callback
//
// Called by the kernel when the scan is complete or aborted
//
// returns NL_SKIP in all cases
//
static int
scan_cb(struct nl_msg *msg, void *arg)
{
    struct genlmsghdr *gmsg = nlmsg_data(nlmsg_hdr(msg));

    switch (gmsg->cmd) {
    case NL80211_CMD_NEW_SCAN_RESULTS:
        LOG(INFO, "NL80211_CMD_NEW_SCAN_RESULTS.");
        *(int*)arg = NLE_SUCCESS;
        break;
    case NL80211_CMD_SCAN_ABORTED:
        LOG(INFO, "NL80211_CMD_SCAN_ABORTED.");
        *(int*)arg = ECONNABORTED;
        break;
    default:
        LOG(INFO, "NL80211_CMD: %d", gmsg->cmd);
        //nl_msg_dump(msg, stdout);
        break;
    }

    return NL_SKIP;
}

// Scan Complete Callback
//
// Called by the kernel per SSID to retrieve the scan data
//
// returns NL_SKIP in all cases
//
static int
scan_complete_cb(struct nl_msg *msg, void *arg)
{
    AccessPoint* ap;
    AccessPoint* tail;
    struct genlmsghdr *gmsg = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *nl_attrs[NL80211_ATTR_MAX + 1];
    struct nlattr *bss[NL80211_BSS_MAX + 1];

    // policy mask copied from iw
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_TSF] = { .type = NLA_U64 },
        [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_BSS_BSSID] = { },
        [NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
        [NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { },
        [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
        [NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
        [NL80211_BSS_STATUS] = { .type = NLA_U32 },
        [NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
        [NL80211_BSS_BEACON_IES] = { },
    };

    nla_parse(nl_attrs, NL80211_ATTR_MAX,
              genlmsg_attrdata(gmsg, 0), genlmsg_attrlen(gmsg, 0), NULL);

    // sanity tests and nested parse...
    if (arg == NULL) {
        LOG(ERROR, "null AP arg!?");
    } else if (!nl_attrs[NL80211_ATTR_BSS]) {
        LOG(ERROR, "no bss info!?");
    } else if (nla_parse_nested(bss, NL80211_BSS_MAX,
                                nl_attrs[NL80211_ATTR_BSS], bss_policy)) {
        LOG(ERROR, "failed to parse nested attributes!");
    } else if ((!bss[NL80211_BSS_FREQUENCY]) ||
               (!bss[NL80211_BSS_BSSID]) ||
               (!bss[NL80211_BSS_INFORMATION_ELEMENTS])) {
        LOG(ERROR, "failed to parse bss attributes!");
    } else {
        // we have valid AP data!
        tail = *(AccessPoint**)arg;
        ap = malloc(sizeof(AccessPoint));
        bzero(ap, sizeof(AccessPoint));

        if (tail == NULL) {
            LOG(DEBUG, "set ap_list head to %p", ap);
            *(AccessPoint**)arg = ap;
        } else {
            while (tail->next != NULL)
                tail = tail->next;

            LOG(DEBUG, "add %p to ap_list tail %p", ap, tail); 
            tail->next = ap;
        }

        parse_bss_info_elements(&bss[NL80211_BSS_INFORMATION_ELEMENTS], ap);
        LOG(INFO,"ssid: %s", ap->ssid);
        memcpy(ap->bssid,
              (unsigned char*)nla_data(bss[NL80211_BSS_BSSID]), BSSID_LEN);
        LOG(INFO,"bssid: %02x:%02x:%02x:%02x:%02x:%02x, ",
            ap->bssid[0], ap->bssid[1], ap->bssid[2],
            ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        ap->channel.frequency = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
        LOG(INFO,"%d MHz", ap->channel.frequency);
        ap->channel.chan_num = convertFrequencyToChannel(ap->channel.frequency);
        LOG(INFO,"chan: %d", ap->channel.chan_num);
        if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
            ap->channel.signal = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
            LOG(INFO,"signal: %d", ap->channel.signal);
        }
        if (bss[NL80211_BSS_SEEN_MS_AGO]) {
            ap->last_seen = nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]);
            LOG(INFO,"last seen: %d", ap->last_seen);
        }
    }

    return NL_SKIP;
}

// Survey Complete Callback
//
// Called by the kernel per SSID to retrieve the Survey data
//
// returns NL_SKIP in all cases
//
static int
survey_complete_cb(struct nl_msg *msg, void *arg)
{
    APChannel* ap_chan;
    struct genlmsghdr* gmsg = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr* nl_attrs[NL80211_ATTR_MAX + 1];
    struct nlattr* survey[NL80211_SURVEY_INFO_MAX + 1];

    // policy mask copied from iw
    static struct nla_policy survey_policy[NL80211_SURVEY_INFO_MAX + 1] = {
        [NL80211_SURVEY_INFO_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_SURVEY_INFO_NOISE] = { .type = NLA_U8 },
    };

    nla_parse(nl_attrs, NL80211_ATTR_MAX,
              genlmsg_attrdata(gmsg, 0), genlmsg_attrlen(gmsg, 0), NULL);

    // sanity tests and nested parse...
    if (arg == NULL) {
        LOG(ERROR, "null APChannel arg!?");
    } else if (!nl_attrs[NL80211_ATTR_SURVEY_INFO]) {
        LOG(ERROR, "no survey info!?");
    } else if (nla_parse_nested(survey, NL80211_SURVEY_INFO_MAX,
                                nl_attrs[NL80211_ATTR_SURVEY_INFO],
                                survey_policy)) {
        LOG(ERROR, "failed to parse nested attributes!");
    } else {
        // we have valid survey data!
        ap_chan = (APChannel*)arg;
        bzero(&ap_chan, sizeof(APChannel));

        if (survey[NL80211_SURVEY_INFO_FREQUENCY]) {
            LOG(ERROR, "failed to parse survey attributes!");
            ap_chan->frequency =
                nla_get_u32(survey[NL80211_SURVEY_INFO_FREQUENCY]);
            LOG(INFO,"%d MHz", ap_chan->frequency);
            ap_chan->chan_num = convertFrequencyToChannel(ap_chan->frequency);
            LOG(INFO,"chan: %d", ap_chan->chan_num);
        }
        if (survey[NL80211_SURVEY_INFO_NOISE]) {
            ap_chan->noise =
                (int8_t)nla_get_u8(survey[NL80211_SURVEY_INFO_NOISE]);
            LOG(INFO,"noise: %d dBm\n", ap_chan->noise);
        }
    }

    return NL_SKIP;
}

// Send a netlink message to the kernel
//
// the sock should have already been obtained from libnl-genl.
//
static int
nl_send_message(struct nl_sock *sock, struct nl_msg *msg, int use_default,
 /* REQUIRED */ int (*valid_cb)(struct nl_msg *msg, void *arg),
                int *val_arg,
 /* OPTIONAL */ int (*finish_cb)(struct nl_msg *msg, void *arg),
                int *fin_arg,
 /* OPTIONAL */ int (*seq_check)(struct nl_msg *msg, void *arg),
                int *seq_arg)
{
    int err;
    int ret;
    struct nl_cb* cb = nl_cb_alloc(NL_CB_DEFAULT);

    if (use_default) {
        nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, valid_cb, val_arg);
        ret = nl_send_auto(sock, msg);
        LOG(INFO, "sent %d bytes to the kernel", __func__, ret);
        ret = nl_recvmsgs_default(sock);
    } else if (cb) {
        nl_cb_err(cb, NL_CB_CUSTOM, error_cb, &ret);
        nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_cb, &ret);
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_cb, val_arg);

        if (finish_cb)
            nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_cb, fin_arg);
        if (seq_check)
            nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, seq_check, seq_arg);

        ret = -ENOBUFS;
        ret = nl_send_auto(sock, msg);

        if (ret >= 0) {
            ret = EINPROGRESS;
            *val_arg = EINPROGRESS;

            while (ret == EINPROGRESS)
                err = nl_recvmsgs(sock, cb);  // wait for ack...

            if (err == 0) {
                while (*val_arg == EINPROGRESS)
                    err = nl_recvmsgs(sock, cb);  // wait for valid...

                switch (*val_arg) {
                case NLE_SUCCESS:
                    LOG(INFO, "success");
                    break;
                case -NLE_PERM:
                    LOG(ERROR, "should to be root");
                    break;
                case -ETIME:
                    LOG(ERROR, "timer expired");
                    break;
                case -ECONNABORTED:
                    LOG(ERROR, "kernel aborted");
                    break;
                default:
                    LOG(INFO, "val_arg: %d", *val_arg);
                    break;
                }

                ret = *val_arg;

            } else {
                LOG(INFO, "%d = nl_recvmsgs, arg: %d", err, ret);
            }

            if (err < 0) {
                LOG(ERROR, "nl_recvmsgs() returned %d (%s).", err,
                       nl_geterror(-err));
                ret = err;
            }
        } else {
            LOG(ERROR, "%d =  nl_send_auto", ret);
        }

    } else {
        LOG(ERROR, "no memory for callbacks");
        return -ENOMEM;
    }

    nl_cb_put(cb);
    return ret;
}

// Send CTRL_CMD_GETFAMILY with 'nl80211' and 'scan' to get the multicast ID
//
// return the multicast ID or an error code
//
static int
get_scan_multicast_id(struct nl_sock *sock)
{
    int ret;
    int mcast_id = -ENOENT;
    struct nl_msg *msg = nlmsg_alloc();
    int ctrlid = genl_ctrl_resolve(sock, "nlctrl");

    if (!msg)
        return -ENOMEM;

    genlmsg_put(msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);
    NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, "nl80211");
    ret = nl_send_message(sock, msg, FALSE,
                          mcast_cb, &mcast_id,
                          NULL, NULL,
                          NULL, NULL);
    if (ret == 0)
        return mcast_id;

nla_put_failure:
    nlmsg_free(msg);
    return ret;
}

// Send NL80211_CMD_TRIGGER_SCAN to start the scan. The kernel may reply with
// NL80211_CMD_NEW_SCAN_RESULTS on success or NL80211_CMD_SCAN_ABORTED if
// another scan was started by another process.
//
// return success or an error code
//
static int
request_scan(struct nl_sock *sock, int if_index, int driver_id, int mcast_id)
{
    struct nl_msg *msg;
    struct nl_msg *ssids_to_scan;
    int ret = EINPROGRESS;
    int err = EINPROGRESS;
    int rval = EINPROGRESS;

    nl_socket_add_membership(sock, mcast_id);

    msg = nlmsg_alloc();
    if (!msg) {
        LOG(ERROR, "Failed to allocate netlink message for msg");
        return -ENOMEM;
    }

    genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    ssids_to_scan = nlmsg_alloc();

    if (!ssids_to_scan) {
        LOG(ERROR, "Failed to allocate netlink message for ssids_to_scan");
        nlmsg_free(msg);
        return -ENOMEM;
    }

    nla_put(ssids_to_scan, 1, 0, "");
    nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids_to_scan);
    nlmsg_free(ssids_to_scan);
    LOG(INFO, "Send NL80211_CMD_TRIGGER_SCAN to the kernel");
    ret = nl_send_message(sock, msg, FALSE,
                          scan_cb, &rval,
                          finish_cb, &err,
                          seq_check_cb, NULL);
    if (ret != 0)
        LOG(WARN, "%d during scan", ret);

    nl_socket_drop_membership(sock, mcast_id);
    nlmsg_free(msg);
    return ret;
}

#else

void
fake_scan_data(void* arg)
{
    int i;
    AccessPoint* ap;
    AccessPoint* tail;

    for (i = 0; i < 10; i++) {
        // we have valid AP data!
        tail = *(AccessPoint**)arg;
        ap = malloc(sizeof(AccessPoint));
        bzero(ap, sizeof(AccessPoint));

        if (tail == NULL) {
            LOG(DEBUG, "set ap_list head to %p", ap);
            *(AccessPoint**)arg = ap;
        } else {
            while (tail->next != NULL)
                tail = tail->next;

            LOG(DEBUG, "add %p to ap_list tail %p", ap, tail); 
            tail->next = ap;
        }

        snprintf(ap->ssid, SSID_LEN, "test_AP_%d", i);
        LOG(INFO,"ssid: %s", ap->ssid);
        ap->bssid[0] = 1;
        ap->bssid[1] = 2;
        ap->bssid[2] = 3;
        ap->bssid[3] = 0;
        ap->bssid[4] = 0;
        ap->bssid[5] = i;
        LOG(INFO,"bssid: %02x:%02x:%02x:%02x:%02x:%02x, ",
            ap->bssid[0], ap->bssid[1], ap->bssid[2],
            ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        if (i < 5)
            ap->channel.frequency = 2412 + (i*5);
        else
            ap->channel.frequency = 5180 + ((i-5)*20);
        LOG(INFO,"%d MHz", ap->channel.frequency);
        ap->channel.chan_num = convertFrequencyToChannel(ap->channel.frequency);
        LOG(INFO,"chan: %d", ap->channel.chan_num);
    }
}

void
fake_survey_data(void* arg)
{
    LOG(INFO,"Not implemented yet...");
}
#endif

// API
// Blocking call to perform the wifi scan (may take several seconds!)
//
// returns the list of APs found during the scan in a singly linked list
//
EXPORT AccessPoint*
wifi_scan(char* interface)
{
    AccessPoint* ret = NULL;
#ifndef __APPLE__
    int if_index = if_nametoindex(interface);
    struct nl_sock *sock = nl_socket_alloc();
    struct nl_msg *msg = nlmsg_alloc();
    int driver_id;
    int mcast_id;
    int err;

    if (!msg) {
        LOG(ERROR, "no memory for message");
        nl_socket_free(sock);
        return ret;
    }

    genl_connect(sock);
    driver_id = genl_ctrl_resolve(sock, "nl80211");
    mcast_id = get_scan_multicast_id(sock);
    err = request_scan(sock, if_index, driver_id, mcast_id);

    if (err != 0) {
        LOG(ERROR, "request_scan() failed with %d", err);
        goto cleanup;
    }

    // get info for all SSIDs found
    genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    err = nl_send_message(sock, msg, TRUE,
                          scan_complete_cb, (int*)&ret,
                          NULL, NULL,
                          NULL, NULL);

    if (err < 0) {
        LOG(ERROR, "%s(%d) = nl_send_message()", nl_geterror(-err), err);
    }

cleanup:
    nlmsg_free(msg);
    nl_socket_free(sock);
#else
    fake_scan_data(&ret);
#endif
    return ret;
}

// API
// Blocking call to perform the wifi scan (may take several seconds!)
//
// returns the list of APs found during the scan in a singly linked list
//
EXPORT APChannel*
wifi_survey(char* interface)
{
    APChannel* ap_chan = NULL;
    APChannel temp = {0};
#ifndef __APPLE__
    int if_index = if_nametoindex(interface);
    struct nl_sock *sock = nl_socket_alloc();
    struct nl_msg *msg = nlmsg_alloc();
    int driver_id;
    int ret = EINPROGRESS;
    int err = EINPROGRESS;

    if (!msg) {
        LOG(ERROR, "no memory for message");
        nl_socket_free(sock);
        return ap_chan;
    }

    genl_connect(sock);
    driver_id = genl_ctrl_resolve(sock, "nl80211");
    genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_GET_SURVEY, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    LOG(INFO, "Send NL80211_CMD_GET_SURVEY to the kernel");
    ret = nl_send_message(sock, msg, FALSE,
                          finish_cb, &err,
                          NULL, NULL,
                          NULL, NULL);
    if (ret != 0)
        LOG(WARN, "%d during survey", ret);

    // get info for all SSIDs found
    genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP,
                NL80211_CMD_NEW_SURVEY_RESULTS, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);
    err = nl_send_message(sock, msg, TRUE,
                          survey_complete_cb, (int*)&temp,
                          NULL, NULL,
                          NULL, NULL);
    if (err < 0) {
        LOG(ERROR, "%s(%d) = nl_send_message()", nl_geterror(-err), err);
    }

cleanup:
    nlmsg_free(msg);
    nl_socket_free(sock);
#else
    fake_survey_data(&ap_chan);
#endif
    return ap_chan;
}

// API
//
// frees the list of APs returned from wifi_scan
//
EXPORT void
free_accesspoint(AccessPoint* ap)
{
    AccessPoint* free_ap = ap;

    while (free_ap != NULL) {
    ap = ap->next;
    LOG(DEBUG, "free %p", free_ap);
        free(free_ap);
        free_ap = ap;
    }
}

// API
// Blocking call to get the suggested AP settings in a APChannel struct
//
// returns the list of APs found during the scan in a singly linked list
//
EXPORT APChannel*
get_suggested_AP_settings(int ghz, AccessPoint* ap_list)
{
    APChannel* ret = NULL;
    int channel = next_least_used_channel(ghz, ap_list);
    LOG(INFO, "(%p) suggested chan = %d", ap_list, channel);

    if (channel) {
        ret = malloc(sizeof(APChannel));
        bzero(ret, sizeof(APChannel));
        ret->chan_num = channel;
        ret->frequency = convertChannelToFrequency(channel);
    }

    return ret;
}

// API
//
// frees the APChannel returned from get_suggested_AP_settings
//
EXPORT void
free_apchannel(APChannel* ap_chan)
{
    LOG(DEBUG, "(%p)", ap_chan);
    free(ap_chan);
}

// API
//
// sends the APChannel returned from get_suggested_AP_settings to a server
//
EXPORT int
save_WIT_settings(APChannel* ap_chan2, APChannel* ap_chan5)
{
    int ret = 0;

    return ret;
}

// API
//
// return the git version (hash) for this library
//
EXPORT unsigned long
get_lib_version(void)
{
    return CLIENT_LIB_VERSION;    // passed in my make -D
}

// API
//
// return the chans list used to determine least used channel
//
EXPORT unsigned int*
get_channel_usage_array(void)
{
    LOG(INFO, "2GHz(%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d)",
        chans[1], chans[2], chans[3], chans[4], chans[5], chans[6],
        chans[7], chans[8], chans[9], chans[10], chans[11]);
    LOG(INFO,
        "5GHz(%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d)",
        chans[36], chans[40], chans[44], chans[48], chans[52], chans[56],
        chans[60], chans[64], chans[100], chans[104], chans[108], chans[112],
        chans[116], chans[132], chans[136], chans[140], chans[149], chans[153],
        chans[157], chans[161], chans[165]);
    return chans;
}

// API
//
// return the frequency for a channel
//
EXPORT unsigned int
get_channel_frequency(int chan)
{
    return convertChannelToFrequency(chan);
}

// API
//
// return the channel for a frequency
//
EXPORT unsigned int
get_frequency_channel(unsigned int freq)
{
    return convertFrequencyToChannel(freq);
}

#undef TEST_LIB
#ifdef TEST_LIB
// only to test this library!!!
int
main(int argc, char **argv)
{
    AccessPoint* ap_list = wifi_scan(argv[1]);
    APChannel* ap_chan2 = get_suggested_AP_settings(2, ap_list);
    int ret = save_WIT_settings(ap_chan2, NULL);

    LOG(INFO, "%x = get_lib_version()", get_lib_version());
    free_accesspoint(ap_list);
    free_apchannel(ap_chan);
    return ret;
}
#endif
