from twisted.application import service, internet
from Crypto.CryptoNode import LoopixCrypto

from Node.AnonymousNode import Create_anonymous_node
from tools.sphinxmix.SphinxParams import SphinxParams
from Crypto.Crypto_Tor import Cryptp_Tor, TorTLSContext


class LoopixNodeSetup:
    def __init__(self, node_set):
        self.info = node_set
        self.nodetype = None
        self.port = None
        self.host = None
        self.name = None
        self.group = None  # 默认值为空
        self.networktype = "Loopix"
    def NodeBuild(self,node_type:str):
        try:
            # 确保 info 至少有 4 个元素
            if len(self.info) < 3:
                raise ValueError("self.info 必须包含至少 3 个元素")

            # 解析端口号
            self.port = int(self.info[0])  # 确保转换为整数
            self.host = self.info[1]
            self.name = self.info[2]

        except ValueError as e:
            print(f"[错误] 端口解析失败: {e}")
            self.port = 0  # 设定默认值

            # **处理可选参数 group**
        if len(self.info) > 3:  # 只有当 sys.argv[3] 存在时才解析
            try:
                self.group = int(self.info[3])
            except ValueError:
                self.group = None  # 仍然设为空值，不影响程序运行

        self.nodetype = node_type
        sec_params = SphinxParams(header_len=1024)
        crypto = LoopixCrypto(sec_params)
        setup = crypto.Loopix_setup()
        curve, private_key, public_key, generator = setup


        created_node = Create_anonymous_node(self.networktype,self.nodetype,sec_params, self.name, self.port, self.host,private_key,public_key,self.group)


        return created_node




class TorNodeSetup:
    def __init__(self, node_set):
        self.info = node_set
        self.nodetype = None
        self.port = None
        self.host = None
        self.name = None
        self.group = None  # 默认值为空
        self.networktype = "Tor"
        self.crypt = Cryptp_Tor()

    def node_init(self,nodetype="client"):

        if nodetype == "client":
            self.client_init()
        elif nodetype == "tornode":
            self.tornode_init()
        elif nodetype == "directory":
            return
        elif nodetype == "bridge":
            return

    #仅初始化作为客户的部分
    def client_init(self):
        self.identitykey = self.crypt.generate_rsa_key()
        self.tls_context = TorTLSContext()

    def tornode_init(self):
        self.identitykey = self.crypt.generate_rsa_key()
        self.tls_context = TorTLSContext(is_public_server=True)

    #bridge部分暂时先跳过
    def bridge_init(self):
        return

    def directory_node_init(self):
        return

