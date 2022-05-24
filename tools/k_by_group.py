from hashlib import sha256

from numpy import uint8

class Group:
    def __init__(self, N: int, g: int):
        self.N: int = N
        self.g: int = g % N
        self.cached_k: int | None = None
    
    def k(self) -> int:
        if not self.cached_k:
            self.cached_k = self._compute_k()
        return self.cached_k

    def _compute_k(self) -> int:
        len_N = (self.N.bit_length() + 7) // 8
        N_bytes: bytes = self.N.to_bytes(len_N, byteorder="big", signed=False)
        g_bytes: bytes = self.g.to_bytes(len_N, byteorder="big", signed=False)

        h = sha256()
        h.update(N_bytes)
        h.update(g_bytes)
        k_bytes: bytes = h.digest() 
        return int.from_bytes(k_bytes, byteorder="big", signed=False)

def main() -> None:
    groups: dict[str, Group] = {}
    groups["1024"] = Group(
        N= 
    0xEEAF0AB9_ADB38DD6_9C33F80A_FA8FC5E8_60726187_75FF3C0B_9EA2314C_9C256576_D674DF74_96EA81D3_383B4813_D692C6E0_E0D5D8E2_50B98BE4_8E495C1D_6089DAD1_5DC7D7B4_6154D6B6_CE8EF4AD_69B15D49_82559B29_7BCF1885_C529F566_660E57EC_68EDBC3C_05726CC0_2FD4CBF4_976EAA9A_FD5138FE_8376435B_9FC61D2F_C0EB06E3,
        g = 2) 

    groups["4096"] = Group(
        N=0xFFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_4FE1356D_6D51C245_E485B576_625E7EC6_F44C42E9_A637ED6B_0BFF5CB6_F406B7ED_EE386BFB_5A899FA5_AE9F2411_7C4B1FE6_49286651_ECE45B3D_C2007CB8_A163BF05_98DA4836_1C55D39A_69163FA8_FD24CF5F_83655D23_DCA3AD96_1C62F356_208552BB_9ED52907_7096966D_670C354E_4ABC9804_F1746C08_CA18217C_32905E46_2E36CE3B_E39E772C_180E8603_9B2783A2_EC07A28F_B5C55DF0_6F4C52C9_DE2BCBF6_95581718_3995497C_EA956AE5_15D22618_98FA0510_15728E5A_8AAAC42D_AD33170D_04507A33_A85521AB_DF1CBA64_ECFB8504_58DBEF0A_8AEA7157_5D060C7D_B3970F85_A6E1E4C7_ABF5AE8C_DB0933D7_1E8C94E0_4A25619D_CEE3D226_1AD2EE6B_F12FFA06_D98A0864_D8760273_3EC86A64_521F2B18_177B200C_BBE11757_7A615D6C_770988C0_BAD946E2_08E24FA0_74E5AB31_43DB5BFC_E0FD108E_4B82D120_A9210801_1A723C12_A787E6D7_88719A10_BDBA5B26_99C32718_6AF4E23C_1A946834_B6150BDA_2583E9CA_2AD44CE8_DBBBC2DB_04DE8EF9_2E8EFC14_1FBECAA6_287C5947_4E6BC05D_99B2964F_A090C3A2_233BA186_515BE7ED_1F612970_CEE2D7AF_B81BDD76_2170481C_D0069127_D5B05AA9_93B4EA98_8D8FDDC1_86FFB7DC_90A6C08F_4DF435C9_34063199_FFFFFFFF_FFFFFFFF,
        g=5)

    for label in groups.keys():
        k = groups[label].k()
        print(f'Group "{label}:\nk={k:x}')

if __name__ == '__main__':
    main()
