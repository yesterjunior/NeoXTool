import os
import argparse
from tqdm import tqdm
import time
import itertools

# ==============================================================================
# 关键设置: 终极版暴力破解字符集
#
# 我们加入了大写字母和下划线
#
CHAR_SET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
KEY_LENGTH = 4


# ==============================================================================

def find_canary_file(input_dir: str) -> tuple[str, bytes] | None:
    """寻找一个合适的“金丝雀”测试文件。"""
    print("正在寻找一个合适的测试样本文件...")
    all_files = sorted(os.listdir(input_dir))
    for filename in all_files:
        path = os.path.join(input_dir, filename)
        if os.path.isfile(path):
            size = os.path.getsize(path)
            if 1024 < size < 51200:
                with open(path, 'rb') as f:
                    print(f"已选择 '{filename}' 作为测试样本。")
                    return filename, f.read()
    if all_files:
        path = os.path.join(input_dir, all_files[0])
        with open(path, 'rb') as f:
            print(f"警告: 未找到理想大小的文件，已选择 '{all_files[0]}' 作为测试样本。")
            return all_files[0], f.read()
    return None


# +++ 核心修改：更智能的、能识别Python和Lua的验证函数 +++
def is_decryption_successful(data: bytes) -> tuple[bool, str]:
    """
    智能验证函数：检查解密后的数据是否像一个Python或Lua脚本。
    返回 (是否成功, 文件类型字符串)
    """
    try:
        text_content = data.decode('utf-8')

        # 检查Python关键词组合
        py_keywords = {'import ', 'def ', 'class ', 'self', 'if __name__'}
        if sum(1 for keyword in py_keywords if keyword in text_content) >= 2:
            return True, 'py'

        # 检查Lua关键词组合
        lua_keywords = {'function', 'local ', 'end', 'require'}
        if sum(1 for keyword in lua_keywords if keyword in text_content) >= 2:
            return True, 'lua'

    except (UnicodeDecodeError, Exception):
        return False, 'dat'  # 解码失败或其它错误，肯定是乱码

    return False, 'dat'


def decrypt_rc4_variant(data: bytes, key: bytes) -> bytes:
    """我们逆向出的 RC4 变体解密算法。"""
    sbox, j = list(range(256)), 0
    key_len = len(key)
    if key_len == 0: return data
    for i in range(256):
        j = (j + sbox[i] + key[i % key_len]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
    i, j = 0, 0
    result = bytearray()
    for char_code in data:
        i = (i + 1) & 0xFF
        j = (j + sbox[i]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
        keystream_byte = sbox[(sbox[i] + sbox[j]) & 0xFF]
        keystream_transformed = ((keystream_byte >> 4) | ((keystream_byte & 0x0F) << 4))
        final_keystream_byte = (keystream_transformed - 92) & 0xFF
        result.append(char_code ^ final_keystream_byte)
    return bytes(result)


def main(input_dir: str, output_dir: str):
    """主函数，生成并遍历所有可能的密钥组合。"""

    canary_sample = find_canary_file(input_dir)
    if not canary_sample:
        print("错误：输入目录中没有任何可供测试的文件。")
        return

    canary_filename, canary_data = canary_sample

    key_generator = itertools.product(CHAR_SET, repeat=KEY_LENGTH)
    total_keys = len(CHAR_SET) ** KEY_LENGTH

    print(f"将使用字符集 '{CHAR_SET}' (共{len(CHAR_SET)}个字符) 来生成并测试 {total_keys} 个密钥。")
    print("这可能需要数小时，请耐心等待...")

    found_key = None
    start_time = time.time()

    for key_tuple in tqdm(key_generator, total=total_keys, desc="暴力破解进度"):
        key_string = "".join(key_tuple)
        key_bytes = key_string.encode('ascii')

        decrypted_data = decrypt_rc4_variant(canary_data, key_bytes)

        success, ext = is_decryption_successful(decrypted_data)

        if success:
            found_key = key_bytes

            if not os.path.exists(output_dir): os.makedirs(output_dir)
            base_name, _ = os.path.splitext(canary_filename)
            new_filename = f"SUCCESS_KEY_{key_string}_{base_name}.{ext}"
            output_path = os.path.join(output_dir, new_filename)
            with open(output_path, 'wb') as f_out:
                f_out.write(decrypted_data)

            break

    end_time = time.time()
    elapsed_minutes = (end_time - start_time) / 60
    print("\n" + "=" * 60)
    if found_key:
        print(f"🎉 恭喜！成功找到解密密钥: '{found_key.decode('ascii')}'")
        print(f"耗时: {elapsed_minutes:.2f} 分钟")
        print(f"已将成功解密的样本文件 '{new_filename}'保存在 '{output_dir}' 目录中。")
    else:
        print(f"😥 遗憾，在指定的字符集和长度内未能找到正确密钥。")
        print(f"耗时: {elapsed_minutes:.2f} 分钟")
        print("逆向分析之旅已达极限，可能密钥包含更特殊的字符或并非4字节。")
    print("=" * 60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='《神都夜行录》终极版全自动密钥破解工具。')
    parser.add_argument('input_dir', type=str, help='包含加密文件的输入目录。')
    parser.add_argument('output_dir', type=str, help='用于保存测试解密后文件的输出目录。')

    args = parser.parse_args()

    main(args.input_dir, args.output_dir)