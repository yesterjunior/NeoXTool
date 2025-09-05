# 文件名: decrypt_shenyedu_npk.py
# 描述: 用于解包并解密《神都夜行录》script.npk文件的完整脚本。
#
# 使用方法:
# 1. 将此代码保存为 decrypt_shenyedu_npk.py
# 2. 确保 key.py 文件在同一目录下
# 3. 运行: python decrypt_shenyedu_npk.py <你的npk文件路径>
#    例如: python decrypt_shenyedu_npk.py script.npk
#
# ** 更新：此版本将输出到 "script_decrypted" 文件夹以避免冲突。**

import os
import struct
import zlib
import tempfile
import argparse
from key import Keys  # 假设 key.py 在同一目录下


# ==============================================================================
# 关键解密算法：基于IDA反编译结果实现的修改版RC4
# ==============================================================================
class ShenduRC4:
    """
    针对《神都夜行录》脚本文件的修改版RC4解密算法。
    密钥(key)是每个文件在NPK索引中存储的CRC32校验和。
    """

    def __init__(self, key_bytes):
        """
        使用给定的密钥初始化RC4状态 (密钥调度算法 KSA)。
        :param key_bytes: 密钥，必须为bytes或bytearray类型，长度为4。
        """
        self.s = list(range(256))
        j = 0
        key_len = len(key_bytes)
        for i in range(256):
            j = (j + self.s[i] + key_bytes[i % key_len]) & 0xFF
            self.s[i], self.s[j] = self.s[j], self.s[i]

        self.i = 0
        self.j = 0

    def crypt(self, data):
        """
        对数据进行加密或解密。
        :param data: 需要处理的数据，bytes或bytearray类型。
        :return: 处理后的bytearray。
        """
        output = bytearray()
        for byte in data:
            # 伪随机生成算法 (PRGA)
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.s[self.i]) & 0xFF
            self.s[self.i], self.s[self.j] = self.s[self.j], self.s[i]
            keystream_byte = self.s[(self.s[self.i] + self.s[self.j]) & 0xFF]

            # 密钥流转换 (算法的关键修改点)
            # 1. 高低四位换位 (Nibble Swap)
            transformed_k = ((keystream_byte >> 4) | (keystream_byte << 4)) & 0xFF
            # 2. 减去 92
            final_key_byte = (transformed_k - 92) & 0xFF

            # 与数据进行XOR
            output.append(byte ^ final_key_byte)

        return bytes(output)


# ==============================================================================
# 从原始 extractor.py 和 onmyoji_extractor.py 整合而来的函数
# ==============================================================================

def readuint32(f):
    return struct.unpack('<I', f.read(4))[0]


def get_ext(data):
    if len(data) < 16:
        if b'Lua' in data: return 'lua'
        return 'txt'
    if data[:4] == b'\x1bLua':
        return 'luac'
    if data[:12] == b'CocosStudio-UI':
        return 'coc'
    elif data.startswith(b'PKM '):
        return 'pkm'
    elif data.startswith(b'PVR\x03'):
        return 'pvr'
    elif data.startswith(b'DDS '):
        return 'dds'
    elif data[1:4] == b'KTX':
        return 'ktx'
    elif data[1:4] == b'PNG':
        return 'png'
    elif data.startswith(b'RIFF') and data[8:12] == b'WAVE':
        return 'wav'
    elif data.startswith(b'BKHD'):
        return 'bnk'
    elif b'<?xml' in data[:100] or b'</' in data[:100]:
        return 'xml'
    elif data.startswith(b'{') and data.endswith(b'}'):
        return 'json'
    elif b'main' in data[:200] and b'function' in data[:200]:
        return 'lua'
    return 'dat'


def unpack(path):
    # --- 主要修改点 ---
    # 将输出文件夹的名称从 'script' 修改为 'script_decrypted'
    base_name = os.path.splitext(path)[0]
    folder_path = base_name + '_decrypted'
    # --- 修改结束 ---

    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    keys = Keys()

    with open(path, 'rb') as f:
        magic = f.read(4)
        pkg_type = None
        if magic == b'NXPK':
            pkg_type = 0
        elif magic == b'EXPK':
            pkg_type = 1
        else:
            raise Exception('错误：不是有效的 NPK 文件 (NXPK/EXPK)')

        print(f"文件类型: {magic.decode('utf-8')}")

        files_count = readuint32(f)
        readuint32(f)  # var1
        readuint32(f)  # var2
        readuint32(f)  # var3
        index_offset = readuint32(f)

        f.seek(index_offset)

        # 读取文件索引表
        index_table_size = files_count * 28
        index_data = f.read(index_table_size)

        # EXPK格式的索引本身是加密的
        if pkg_type == 1:
            index_data = keys.decrypt(index_data)

        index_table = []
        with tempfile.TemporaryFile() as tmp:
            tmp.write(index_data)
            tmp.seek(0)
            for _ in range(files_count):
                file_sign = readuint32(tmp)
                file_offset = readuint32(tmp)
                file_length = readuint32(tmp)
                file_original_length = readuint32(tmp)
                zcrc = readuint32(tmp)  # zlib compressed crc
                crc = readuint32(tmp)  # original crc
                file_flag = readuint32(tmp)
                index_table.append((
                    file_sign,
                    file_offset,
                    file_length,
                    file_original_length,
                    crc,
                    file_flag,
                ))

        print(f"在索引中找到 {files_count} 个文件。开始提取和解密...")

        # 提取、解密、解压并保存每个文件
        for i, item in enumerate(index_table):
            file_sign, file_offset, file_length, file_original_length, crc, file_flag = item

            f.seek(file_offset)
            data = f.read(file_length)

            # 步骤 1: NPK包级解密 (仅对EXPK)
            if pkg_type == 1:
                data = keys.decrypt(data)

            zflag = file_flag & 0xFFFF
            eflag = file_flag >> 16

            # 步骤 2: 文件内容级解密 (神都RC4算法)
            if pkg_type == 1 and crc != 0:
                try:
                    key_as_bytes = struct.pack('<I', crc)
                    rc4_decryptor = ShenduRC4(key_as_bytes)
                    data = rc4_decryptor.crypt(data)
                except Exception as e:
                    print(f"警告：文件 {i} 使用CRC {hex(crc)} 进行RC4解密失败: {e}")

            # 步骤 3: zlib解压缩
            if zflag == 1:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    print(f"警告：文件 {i} zlib解压失败，可能未压缩或已损坏。")
                    pass

            # 步骤 4: 确定扩展名并保存
            ext = get_ext(data)
            file_name = f'{i:08d}.{ext}'
            file_path = os.path.join(folder_path, file_name)

            with open(file_path, 'wb') as out_f:
                out_f.write(data)

            print(f"  ({i + 1}/{files_count}) -> {file_path} [CRC: {hex(crc)}]")

    print("\n提取和解密完成！")
    print(f"所有文件已保存到 '{folder_path}' 文件夹中。")


def main():
    parser = argparse.ArgumentParser(description='《神都夜行录》NPK文件提取和解密工具')
    parser.add_argument('path', type=str, help='要处理的.npk文件路径 (例如 script.npk)')
    opt = parser.parse_args()

    if not os.path.exists(opt.path):
        print(f"错误：文件 '{opt.path}' 不存在。")
        return

    try:
        unpack(opt.path)
    except Exception as e:
        print(f"\n处理过程中发生严重错误: {e}")


if __name__ == '__main__':
    main()