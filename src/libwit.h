/*
 * wifiscan.h: detect all access points using NL80211 (netlink).
 *
 */

#ifndef __WIFISCAN_H__
#define __WIFISCAN_H__

#define TRUE    1
#define FALSE   0

#define SSID_LEN    32
#define BSSID_LEN   6
#define MAX_CHANS   166

#define EXPORT __attribute__((__visibility__("default")))

typedef struct apchannel {	// this struct is manually packed
    unsigned char chan_num;
    char signal;
    unsigned char stations;
    unsigned char utilization;
    unsigned int frequency;
    int noise;
} APChannel;

typedef struct chanarray {
    unsigned int count;
    struct apchannel channel[];
} ChanArray;

typedef struct accesspoint {	// this struct is manually packed
    struct accesspoint* next;
    unsigned short if_index;
    unsigned char bssid[BSSID_LEN];
    char ssid[SSID_LEN];
    unsigned int last_seen;
    struct apchannel channel;
} AccessPoint;


extern AccessPoint* wifi_scan(char* interface);
extern APChannel* wifi_survey(char* interface);
extern void free_accesspoint(AccessPoint* ap);
extern APChannel* get_suggested_AP_settings(int ghz, AccessPoint* ap_list);
extern void free_apchannel(APChannel* ap_chan);
extern int save_WIT_settings(APChannel* ap_chan2, APChannel* ap_chan5);
extern unsigned long get_lib_version(void);
extern unsigned int* get_channel_usage_array(void);
extern unsigned int get_channel_frequency(int chan);
extern unsigned int get_frequency_channel(unsigned int freq);

#endif
