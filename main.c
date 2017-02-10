#include "main.h"    
#include "clt_cm.h"
#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "unistd.h"


void call_back_test(struct cm_msg *p_msg){
    printf("Rcv msg:%s cnt:%d\n",p_msg->data,p_msg->msg_cnt);
    fflush(stdout);
}

int main(){
    struct clt_s *pcs;
    int login_result;
    char req_data[] = "I want to know all the users who have login.";

    pcs = clt_create(NULL);
    strcpy(pcs->server_ip,"192.168.1.6");
    pcs->server_port = 1080;
    pcs->id = 1;
    strcpy(pcs->usr_name,"yiran");
    strcpy(pcs->usr_passwd,"snivwkbsk123");
    clt_login(pcs,&login_result);
    printf("login_result:%d,err:%s",login_result,strerror(errno));
    fflush(stdout);
    clt_add_req_cb(pcs,call_back_test,1);
    while(1){
        clt_request(pcs,1,req_data,strlen(req_data)+1);
        sleep(1);
    }
    return 1;
}
