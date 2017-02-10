#include "stdio.h"
#include "stdlib.h" 
#include "string.h"  
#include "unistd.h"
#include "errno.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "sys/time.h"
#include "fcntl.h"
#include "pthread.h"
#include "signal.h"
#include "mmpool.h"
#include "clt_cm.h"
#include "encdec.h"
#include "tdpool.h"




/* 函数名: int __rcv_data(int sockfd,char *rcv_buf,int buf_size)
 * 功能: 从套接字上接收一个数据包，内部调用
 * 参数: int sockfd,套接字描述符
 *       char *rcv_buf,接收数据的缓存
 *       int buf_size,缓存大小
 * 返回值: -1,接受数据出现了错误
 *        >=0,实际接受大小
 */
int __rcv_data(int sockfd,char *rcv_buf,int buf_size){
    struct timeval timeout;   //设置超时用
    unsigned short rcv_size = 0;
    int syc_cnt = 0;  //同步计数
    int monitor_cnt = 0; //监听字符计数
    int h_i = 0; //接收head的index
    union{
        unsigned short u16;
        unsigned char u8[2];
    }head;
    const char syc_c = '\r';  //同步字符
    const char ctl_c = 0x10;  //控制字符
    char rcv_c;
    int rcv_status = 0;//0,处于监听状态，1处于报文接收状态

    timeout.tv_sec = 5;  //5秒钟超时
    timeout.tv_usec = 0;
    //设置接收超时
    setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(struct timeval));

    while(1){
        if(rcv_status == 0){  //处于报文接收状态
            if(monitor_cnt++ == 50){ //如果监听的字符计数超过了50则退出
                return -1;
            }
            if(recv(sockfd,&rcv_c,1,0) == -1){
                return -1;
            }
            if(rcv_c == syc_c){
                if(++syc_cnt == 3){  //开始接收head
                    while(1){
                        if(recv(sockfd,&rcv_c,1,0) == -1){
                            return -1;
                        }
                        if(rcv_c == syc_c)continue;
                        if(rcv_c == ctl_c){
                            if(recv(sockfd,&rcv_c,1,0) == -1){
                                return -1;
                            }
                        }
                        head.u8[h_i++] = rcv_c;
                        if(h_i == 2){
                            rcv_status = 1;
                            rcv_size = head.u16 >> 1;
                            if(rcv_size > buf_size)return -1;
                            break;
                        }
                    }
                }
            }else{
                syc_cnt = 0;
            }
        }else if(rcv_status == 1){
            if(recv(sockfd,rcv_buf,rcv_size,0) == -1){
                return -1;
            }
            break;
        }
    }
    return 1;
    
}

/* 函数名: int __snd_msg_test(int sockfd,struct msg *snd_msg)
 * 功能: 通过套接字发送一段数据，为内部调用
 * 参数:
 * 返回值:
 */
int __snd_data(int sockfd,char *data,unsigned short data_size){
    unsigned short snd_size;
    unsigned short real_snd_size;
    union{
        unsigned short u16;
        char u8[2];
    }head;
    const char syc_char = '\r'; //同步符号
    const char ctl_char = 0x10;
    int i;
    snd_size = data_size;
    head.u16 = (snd_size << 1) | 0; //不加密
    for(i = 0;i < 5;i++){
        send(sockfd,&syc_char,1,0);  //发送3个同步符号
    }
    for(i = 0;i < 2;i++){
        if(head.u8[i] == syc_char){
            send(sockfd,&ctl_char,1,0);
            send(sockfd,&head.u8[i],1,0);
        }else{
            send(sockfd,&head.u8[i],1,0);
        }
    }
    real_snd_size = send(sockfd,data,snd_size,0); //发送报文
    return 1;
}


/* 函数名: int __snd_aes_msg(int sockfd,struct msg *snd_msg,AES_KEY *enc_key)
 * 功能: 发送aes加密的报文,内部调用
 * 参数: int sockfd，发送的套接字
 *       struct msg *snd_msg,消息结构体
 *       AES_KEY *enc_key,加密的秘钥
 * 返回值:
 */
int __snd_aes_msg(int sockfd,struct cm_msg *snd_msg,AES_KEY *enc_key){
    char cipher[CLT_MAX_DATA_SIZE]; 
    memset(cipher,0,4096);
    aes_cbc_enc(enc_key,(unsigned char *)snd_msg,(unsigned char*)cipher,snd_msg->data_size + sizeof(struct cm_msg) - CLT_MAX_DATA_SIZE);
    __snd_data(sockfd,cipher,((snd_msg->data_size + sizeof(struct cm_msg) - CLT_MAX_DATA_SIZE)/16 + 1)*16);
    return 1;
}

/* 函数名: void *recv_thread(void*)
 * 功能: 接收线程
 * 参数:
 * 返回值:
 */
void *recv_thread(void* arg){
    int recv_status = 0;  //接收状态，0为监听，1为报文接收状态
    int recv_size;
    int syc_cnt = 0;
    int h_i;
    int enc_flag;
    const char syc_char = '\r';
    char recv_c;
    char recv_buf[CLT_MAX_DATA_SIZE];
    struct clt_s *pcs;
    struct cm_msg recv_msg;
    union{
        unsigned short u16;
        unsigned char u8[2];
    }head;
    pcs = (struct clt_s*)arg;
    while(1){
        if(pcs->login_state == 0){ 
            /*如果没有登录*/
            sleep(1);
            continue;
        }
        if(recv_status == 0){  //处于监听状态
            recv(pcs->sockfd,&recv_c,1,0);
            if(recv_c == syc_char){
                if(++syc_cnt == 3){
                    h_i = 0;
                    while(1){
                        recv(pcs->sockfd,&recv_c,1,0);
                        if(recv_c == syc_char)continue;
                        if(recv_c == 0x10){
                            recv(pcs->sockfd,&recv_c,1,0);
                        }
                        head.u8[h_i++] = recv_c;
                        if(h_i == 2){
                            syc_cnt = 0;
                            recv_status = 1; //置为报文接收状态
                            recv_size = head.u16 >> 1;
                            enc_flag = head.u16 & 1; //加密标志
                            break;
                        }
                    }
                }
            }else{
                syc_cnt = 0;
            }
        }else{
            /*如果处于报文接收状态*/
            recv(pcs->sockfd,&recv_buf,recv_size,0);
            if(enc_flag == 1){
                aes_cbc_dec(&pcs->aes_dec_key,(unsigned char*)recv_buf,(unsigned char *)&recv_msg,recv_size);
            }else{
                memcpy(&recv_msg,recv_buf,recv_size);
            }
            if(recv_msg.type == 2 && pcs->req_call_back_array[recv_msg.req_type] != 0){ 
                /*如果是请求报文，则使用线程池中的线程调用相应的请求回调函数*/
                tdpl_call_fun(pcs->tdpl,pcs->req_call_back_array[recv_msg.req_type],&recv_msg,sizeof(recv_msg));
            }
            recv_status = 0;
        }
    }
}

/* 函数名: void *heart_beat_thread(void *arg)
 * 功能: 心跳线程，定期给服务端发送心跳报文
 * 参数:
 * 返回值:
 */
void *heart_beat_thread(void *arg){
    struct cm_msg heart_beat_msg;
    struct clt_s *pcs;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE,NULL); //使能线程取消
    /* 设置异步取消，因为只有在客户端创建失败或者销毁客户端的时候才会关闭心跳线程
     * ，所以就不用管线程执行到了哪里，直接取消掉线程。*/
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL); 
    pcs = (struct clt_s*)arg;
    heart_beat_msg.type = 4;
    heart_beat_msg.data_size = 0;
    heart_beat_msg.client_id = pcs->id;
    while(1){
        /*如果已经登录，则发送心跳报文*/
        if(pcs->login_state == 1){
            sem_wait(&pcs->snd_mutex);
            __snd_aes_msg(pcs->sockfd,&heart_beat_msg,&pcs->aes_enc_key);
            sem_post(&pcs->snd_mutex);
            printf("heart beat\n");
            fflush(stdout);
        }
        sleep(pcs->heart_beat_period);
    }
}


/* 函数名: int clt_add_req_cb(struct clt_s *pcs,void (*call_back_fun)(struct cm_msg p_msg),int req_n)
 * 功能: 添加请求回调函数
 * 参数: struct clt_s *pcs,客户端结构体指针
 *       void (*call_back_fun)(struct cm_msg *p_msg),回调函数地址
 *       int req_n,请求号
 * 返回值: -1,添加失败
 *          1,添加成功
 */
int clt_add_req_cb(struct clt_s *pcs,void (*call_back_fun)(struct cm_msg *p_msg),int req_n){
    if(pcs == NULL || call_back_fun == NULL){
        return -1;
    }
    if(pcs->req_call_back_array[req_n] != 0){ //已经存在回调函数
        return -1;
    }
    pcs->req_call_back_array[req_n] = call_back_fun;
    return 1;
}

/* 函数名: int clt_login(struct clt_s *pcs,int *res)
 * 功能: 客户端登录
 * 参数: struct clt_s *pcs,指向客户端结构体的指针
 *       int *res,返回登录结果信息
 * 返回值: -1,登录出现了错误
 *          1,登录成功
 */
int clt_login(struct clt_s *pcs,int *res){
    struct sockaddr_in servaddr;  
    char remote_rsa_pubkey[CLT_RSA_KEY_LENGTH];
    char local_rsa_pubkey[CLT_RSA_KEY_LENGTH];
    char local_rsa_privkey[CLT_RSA_KEY_LENGTH];
    char plain[CLT_MAX_DATA_SIZE];
    char cipher[CLT_MAX_DATA_SIZE];
    unsigned char aes_key[CLT_AES_KEY_LENGTH/8];
    int login_result;
    int result_value;
    if(pcs == NULL || res == NULL){
        goto err1_ret;
    }
    memset(&servaddr,0,sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;  
    servaddr.sin_port = htons((pcs->server_port));
    /*把字符串形式的IP转换成标准形式*/
    if(inet_pton(AF_INET,pcs->server_ip, &servaddr.sin_addr) == -1){  
        login_result = errno;
        goto err2_ret;
    }  
    /*连接服务器*/
    if(connect(pcs->sockfd,(struct sockaddr*)&servaddr,sizeof(struct sockaddr_in)) == -1){  
        login_result = errno;
        goto err2_ret;
    }  
    /*发送用户名*/
    if((__snd_data(pcs->sockfd,pcs->usr_name,strlen(pcs->usr_name) + 1)) <= 0){
        login_result = errno;
        goto err3_ret;
    }
    /*接受远程公钥，也有可能接收到错误号*/
    if((__rcv_data(pcs->sockfd,remote_rsa_pubkey,CLT_RSA_KEY_LENGTH)) == -1){   
        login_result = errno;
        goto err3_ret;
    }
    if(*(int *)remote_rsa_pubkey == CLT_ERR_USRNOTEXIST){
        /*用户不存在*/
        login_result = CLT_ERR_USRNOTEXIST;
        goto err3_ret;
    }
    /*生成本地rsa密钥对*/
    rsa_gen_keys(CLT_RSA_KEY_LENGTH,local_rsa_pubkey,local_rsa_privkey);
    /*组装认证内容并且使用本地RSA公约加密*/
    sprintf(plain,"%s+%s",pcs->usr_passwd,local_rsa_pubkey);
    if(rsa_pub_encrypt(remote_rsa_pubkey,plain,cipher) == -1){
        login_result = CLT_ERR_RSA_PUBENC_FAILED;
        goto err3_ret;
    }
    /*发送认证内容*/
    if(__snd_data(pcs->sockfd,cipher,strlen(cipher)) == -1){
        login_result = errno;
        goto err3_ret;
    }
    /*接收结果*/
    if(__rcv_data(pcs->sockfd,(char *)&result_value,sizeof(int)) == -1){
        login_result = errno;
        goto err3_ret;
    }
    if(result_value != CLT_LOGIN_SUCCESS){
        /*如果认证不成功*/
        login_result = result_value;
        goto err3_ret;
    }
    /*此时虽然登录成功了，但是要做一些成功后的工作*/
    /*接收AES密钥*/
    if(__rcv_data(pcs->sockfd,cipher,CLT_MAX_DATA_SIZE) == -1){
        login_result = errno;
        goto err3_ret;
    }
    if(rsa_priv_decrypt(local_rsa_privkey,cipher,plain) == -1){
        login_result = CLT_ERR_RSA_PRIVDEC_FAILED;
        goto err3_ret;
    }
    memcpy(aes_key,plain,CLT_AES_KEY_LENGTH/8);
    AES_set_encrypt_key(aes_key,CLT_AES_KEY_LENGTH,&pcs->aes_enc_key);
    AES_set_decrypt_key(aes_key,CLT_AES_KEY_LENGTH,&pcs->aes_dec_key);
    pcs->login_state = 1; //设置登录状态
    *res = CLT_LOGIN_SUCCESS;
    return 1;
err3_ret:
    /*关闭连接*/
    shutdown(pcs->sockfd,SHUT_RDWR);
err2_ret:
    *res = login_result;
err1_ret:
    return -1;
}


/* 函数名: struct clt_s* clt_create(struct clt_opt_s *p_cos)
 * 功能: 创建客户端
 * 参数: struct ctl_opt_s *p_cos,指向客户端选项结构体的指针
 * 返回值: NULL,创建失败
 *        !NULL,客户端结构体指针
 */
struct clt_s* clt_create(struct clt_opt_s *p_cos){
    struct clt_s *p_new_cs;
    struct mm_pool_s *clt_mmpl = NULL;
    int sockfd;

    mmpl_create(&clt_mmpl);
    if(clt_mmpl == NULL){
        goto err1_ret;
    }
    /*为客户端结构体向内存池申请空间*/
    p_new_cs = mmpl_getmem(clt_mmpl,sizeof(struct clt_s));
    if(p_new_cs == NULL){
        goto err2_ret;
    }
    memset(p_new_cs,0,sizeof(struct clt_s));
    if(p_cos == NULL){
        /*当选项结构体指针是空的时候，使用默认选项*/
        p_new_cs->heart_beat_period = CLT_HEART_BEAT_DF;
        p_new_cs->tdpl_thread_num = CLT_TDPL_THREAD_NUM_DF;
        p_new_cs->tdpl_max_reqq = CLT_TDPL_MAX_REQQ_DF;
    }else{
        p_new_cs->heart_beat_period = p_cos->heart_beat_period;
        p_new_cs->tdpl_thread_num = p_cos->tdpl_thread_num;
        p_new_cs->tdpl_max_reqq = p_cos->tdpl_max_reqq;
    }
    /*创建线程池*/
    p_new_cs->tdpl = tdpl_create(p_new_cs->tdpl_thread_num,p_new_cs->tdpl_max_reqq);
    if(p_new_cs->tdpl == NULL){
        goto err2_ret;
    }
    if((sockfd = socket(AF_INET,SOCK_STREAM,0)) == -1){  //创建套接字
        goto err3_ret;
    }
    p_new_cs->sockfd = sockfd;
    /*创建心跳线程*/
    if(pthread_create(&p_new_cs->heart_beat_tid,NULL,heart_beat_thread,p_new_cs) == -1){
        goto err4_ret;
    }
    /*创建报文接收线程*/
    if(pthread_create(&p_new_cs->rcv_tid,NULL,recv_thread,p_new_cs) == -1){
        goto err5_ret;
    }
    /*初始化发送互斥锁*/
    sem_init(&p_new_cs->snd_mutex,0,1);

    return p_new_cs;

    /*以下是创建失败之后所需要处理的事情的代码*/
err5_ret:
    pthread_cancel(p_new_cs->heart_beat_tid);
    pthread_join(p_new_cs->heart_beat_tid,NULL);
err4_ret:
    close(sockfd);
err3_ret:
    tdpl_destroy(p_new_cs->tdpl);
err2_ret:
    mmpl_destroy(clt_mmpl);
err1_ret:
    return NULL;
}

/* 函数名: int clt_request(struct clt_s *pcs,int req_n,char *req_data)
 * 功能: 向服务器发送请求
 * 参数: struct clt_s *pcs,客户端结构体
 *       int req_n,请求号
 *       char *req_data,请求内容
 *       int data_size,请求内容的大小
 * 返回值: -1,
 *          1,
 */
int clt_request(struct clt_s *pcs,int req_n,char *req_data,int data_size){
    struct cm_msg snd_msg;

    if(pcs == NULL){
        return -1;
    }
    if(req_data == NULL && data_size != 0){
        return -1;
    }
    if(pcs->login_state == 0){
        /*如果没有登录，则无法发送请求*/
        return -1;
    }
    if(data_size > CLT_MAX_DATA_SIZE){
        return -1;
    }
    snd_msg.client_id = pcs->id;
    snd_msg.type = 2;
    snd_msg.req_type = req_n;
    snd_msg.data_size = data_size;
    memcpy(snd_msg.data,req_data,data_size);
    if(__snd_aes_msg(pcs->sockfd,&snd_msg,&pcs->aes_enc_key) == -1){
        return -1;
    }
    return 1;
}

