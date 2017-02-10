#include "encdec.h" 
#include "semaphore.h"


#define CLT_MAX_DATA_SIZE 4096
#define CLT_HEART_BEAT_DF 5
#define CLT_TDPL_THREAD_NUM_DF 20   /*默认的线程池线程数*/
#define CLT_TDPL_MAX_REQQ_DF 500  /*默认的线程池请求队列最大长度*/
#define CLT_RSA_KEY_LENGTH 1024
#define CLT_AES_KEY_LENGTH 128
#define CLT_MAX_REQ_NUM 4096  /*最大请求号*/

/*下面是一些状态号的定义*/
#define CLT_LOGIN_SUCCESS 1


/*下面是错误号的定义*/
#define CLT_ERR_USRNOTEXIST 29  /*用户名不存在*/
#define CLT_ERR_INCORRECT_PASSWD 30  /*密码错误*/
#define CLT_ERR_MUL_LOGIN 31  /*重复登录*/
#define CLT_ERR_BADADDR 101  /*使用了坏的内存地址*/
#define CLT_ERR_RSA_PUBENC_FAILED 102  /*使用RSA公约加密失败*/
#define CLT_ERR_RSA_PRIVDEC_FAILED 103  /*使用RSA私钥解密失败*/

/*通信报文格式*/
struct cm_msg{
    unsigned int client_id;
    unsigned short type;
    unsigned short req_type;
    unsigned int msg_cnt;
    unsigned short data_size;
    unsigned short check_sum;
    unsigned char data[CLT_MAX_DATA_SIZE];
};

struct clt_opt_s{
    unsigned int tdpl_thread_num; //线程池线程数
    unsigned int tdpl_max_reqq;  //线程池最大请求队列长度
    unsigned int heart_beat_period;

};


struct clt_s{
    int sockfd;  //套接字
    char server_ip[16]; //字符串形式的ip
    unsigned short server_port; //服务器端口
    unsigned short local_port; //本地端口
    
    int id;
    char usr_name[64];  //用户名
    char usr_passwd[64]; //用户密码
    int lv; //用户权限
    int login_state; //登录状态，0为未登录，1为已登录
    AES_KEY aes_enc_key,aes_dec_key; //aes加解密钥

    unsigned int heart_beat_period; //心跳周期
    struct mm_pool_s *mmpl;  //客户端使用的内存池
    struct tdpl_s *tdpl;  //请求响应所需要的线程池
    unsigned int tdpl_thread_num; //线程池线程数
    unsigned int tdpl_max_reqq;  //线程池最大请求队列长度
    unsigned long rcv_tid; //接受报文的线程的id
    unsigned long heart_beat_tid; //心跳线程id
    sem_t snd_mutex;  //发送互斥锁
    void *req_call_back_array[CLT_MAX_REQ_NUM]; //请求回调函数数组
};

int clt_add_req_cb(struct clt_s *pcs,void (*call_back_fun)(struct cm_msg *p_msg),int req_n);
int clt_login(struct clt_s *pcs,int *res);
int clt_request(struct clt_s *pcs,int req_n,char *req_data,int data_size);
struct clt_s* clt_create(struct clt_opt_s *p_cos);
