import os
import argparse
from tqdm import tqdm

# ==============================================================================
# 关键设置 (KEY CONFIGURATION)
#
# 这是我们整个逆向工程项目的最后一步。
# 你需要将下面的占位符密钥替换为真实的4字节解密密钥。
#
# 如何验证密钥是否正确？
# 1. 修改下面的 DECRYPTION_KEY。
# 2. 运行脚本。
# 3. 查看输出文件夹，如果里面的 .png 文件可以正常打开为图片，
#    或者 .xml/.json 文件是可读的文本，那么密钥就是正确的！
#
DECRYPTION_KEY = b'ajog'  # <-- 在这里填入你找到的4字节密钥！
# ==============================================================================


def get_ext(data: bytes) -> str:
    """
    根据文件内容（魔法数字）来判断文件的真实扩展名。
    """
    if len(data) < 16:
        return 'dat'  # 文件太小，无法判断

    if data.startswith(b'\x89PNG'):
        return 'png'
    elif data.startswith(b'PKM'):
        return 'pkm'
    elif data.startswith(b'PVR'):
        return 'pvr'
    elif data.startswith(b'DDS'):
        return 'dds'
    elif data[1:4] == b'KTX':
        return 'ktx'
    elif data.startswith(b'CocosStudio-UI'):
        return 'csb'
    elif data.startswith(b'<?xml'):
        return 'xml'
    elif data.startswith(b'{') or data.startswith(b'['):
        return 'json'
    elif data.startswith(b'RIFF'):
        return 'wav'
    elif data.startswith(b'BKHD'):
        return 'bnk'
    # 可以根据需要继续添加其他文件类型的判断
    return 'dat'  # 无法识别则保留 dat


def decrypt_rc4_variant(data: bytes, key: bytes) -> bytes:
    """
    根据 IDA 中 sub_27FDBD0 的逻辑，完整复现的 RC4 变体解密算法。

    参数:
    data (bytes): 需要解密的加密数据。
    key (bytes): 用于密钥调度阶段的密钥。

    返回:
    bytes: 解密后的数据。
    """
    # 1. S-Box 初始化 (KSA Part 1)
    sbox = list(range(256))

    # 2. S-Box 乱序 (KSA Part 2)
    j = 0
    key_len = len(key)
    if key_len == 0:
        raise ValueError("Key cannot be empty.")

    for i in range(256):
        j = (j + sbox[i] + key[i % key_len]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]  # 交换

    # 3. 生成密钥流并进行异或 (PRGA)
    i = 0
    j = 0
    result = bytearray()

    for char_code in data:
        i = (i + 1) & 0xFF
        j = (j + sbox[i]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]  # 交换

        keystream_byte = sbox[(sbox[i] + sbox[j]) & 0xFF]

        # C++ 代码中的微小变体：对密钥字节进行 4 位的循环右移(ROR)，然后减去 92
        keystream_transformed = ((keystream_byte >> 4) | ((keystream_byte & 0x0F) << 4))
        final_keystream_byte = (keystream_transformed - 92) & 0xFF

        decrypted_char = char_code ^ final_keystream_byte
        result.append(decrypted_char)

    return bytes(result)


def main(input_dir: str, output_dir: str):
    """
    主函数，处理指定目录中的所有文件，进行解密并保存。
    """
    if not os.path.isdir(input_dir):
        print(f"错误：输入目录 '{input_dir}' 不存在或不是一个文件夹。")
        return

    if not os.path.exists(output_dir):
        print(f"创建输出目录：'{output_dir}'")
        os.makedirs(output_dir)

    print(f"开始处理目录 '{input_dir}'...")
    print(f"使用的密钥: {DECRYPTION_KEY}")
    if DECRYPTION_KEY == b'KEY?':
        print("警告：你正在使用占位符密钥，解密结果很可能是错误的！请修改脚本中的 DECRYPTION_KEY。")

    file_list = [f for f in os.listdir(input_dir) if os.path.isfile(os.path.join(input_dir, f))]

    for filename in tqdm(file_list, desc="解密进度", unit="个文件"):
        input_path = os.path.join(input_dir, filename)

        try:
            with open(input_path, 'rb') as f_in:
                encrypted_data = f_in.read()

            if not encrypted_data:
                continue

            decrypted_data = decrypt_rc4_variant(encrypted_data, DECRYPTION_KEY)

            ext = get_ext(decrypted_data)

            base_name, _ = os.path.splitext(filename)
            new_filename = f"{base_name}.{ext}"
            output_path = os.path.join(output_dir, new_filename)

            with open(output_path, 'wb') as f_out:
                f_out.write(decrypted_data)

        except Exception as e:
            tqdm.write(f"处理文件 '{filename}' 时出错: {e}")

    print("\n所有文件处理完毕！")
    print(f"解密后的文件已保存至 '{output_dir}' 目录。")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='《神都夜行录》.dat 文件解密工具。',
        epilog='使用前请务必在脚本中设置正确的 DECRYPTION_KEY！'
    )
    parser.add_argument('input_dir', type=str, help='包含加密文件的输入目录 (例如: res)。')
    parser.add_argument('output_dir', type=str, help='用于保存解密后文件的输出目录 (例如: res_decrypted)。')

    args = parser.parse_args()

    main(args.input_dir, args.output_dir)