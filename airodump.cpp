#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <libnet.h>
#include <list>

using namespace std;

struct ieee80211_radiotap_header {
    u_int8_t it_version;     /* set to 0 */
    u_int8_t it_pad;
    u_int16_t it_len;         /* entire length */
    u_int32_t it_present;     /* fields present */
};

struct ieee80211_header {
    uint8_t type;
    uint8_t flags_control;
    uint16_t duration;
    uint8_t DMac[6];
    uint8_t SMAC[6];
    uint8_t BSSID[6];
    uint16_t frag_seq_number;
};

struct Beaconframe{
	uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capacity_informaion;
    uint8_t elementid;
    uint8_t length; 
};

struct node{
	int beacons;
    uint8_t bssid[6];
}; 

std::list<node*> nodelist;

void usage(){
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan1\n");
}

struct ieee80211_radiotap_header *RT;
struct ieee80211_header *HD;
struct Beaconframe *BF;

void print_info(const u_char* packet){
    int n = 1;
    RT = (struct ieee80211_radiotap_header*)packet;
    HD = (struct ieee80211_header*)(packet + RT->it_len);
    BF = (struct Beaconframe*)(packet + RT->it_len + sizeof(ieee80211_header));

    if(HD->type != 0x80){
        puts("[*] It's Not a Beacon Frame! [*]");
        return;
    }

    for(node* ptr : nodelist){
        if(!memcmp(ptr->bssid, HD->BSSID, 6)){
            ptr->beacons = ptr->beacons + 1;
            n = 0;
        }
    }

    if(n){
        struct node* newbss = (node*)malloc(sizeof(node));
        memcpy(newbss->bssid, HD->BSSID, 6);
        newbss->beacons = 1;
    }

    int beacons;
    for(node* ptr : nodelist){
        if(!memcmp(ptr->bssid, HD->BSSID, 6)) beacons = ptr->beacons;
    }

    int len = BF->length;
    char ssid[100] = {0,};
    memcpy(ssid, (char*)BF+14, len);

    printf("[*] BSSID : ");
    for(int i=0; i<5; i++){
        printf("%02x:", HD->BSSID[i]);
    }
    printf("%02x\n", HD->BSSID[5]);

    printf("[*] Beacon : %d\n", beacons);

    printf("[*] SSID : ");
    for(int i=0; i<=len; i++){
        printf("%c:", ssid[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]){

    if (argc !=2){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle= pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle==nullptr){
        fprintf(stderr,"couldn't open device %s(%s)\n",dev,errbuf);
        return -1;
    }
    
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header,&packet);
        if (res == 0) continue;
        if (res==-1 || res==-2) break;
        print_info(packet);
    }
    pcap_close(handle);
    return 0;
}