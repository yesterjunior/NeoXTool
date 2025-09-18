import os
import struct
import zlib
import argparse


def read_uint32(f):
    """从文件对象中读取一个32位无符号整数（小端序）"""
    return struct.unpack('<I', f.read(4))[0]


def get_ext(data):
    """根据文件数据内容猜测文件扩展名"""
    if not data:
        return 'none'

    # 优先根据明确的文件签名判断
    if data.startswith(b'CocosStudio-UI'): return 'coc'
    if data.startswith(b'<'): return 'xml'
    if data.startswith(b'{'): return 'json'
    if data.startswith(b'hit'): return 'hit'
    if data.startswith(b'PKM'): return 'pkm'
    if data.startswith(b'PVR'): return 'pvr'
    if data.startswith(b'DDS'): return 'dds'
    if data[1:4] == b'KTX': return 'ktx'
    if data[1:4] == b'PNG': return 'png'
    if data.startswith(bytes([0x34, 0x80, 0xC8, 0xBB])): return 'mesh'
    if data.startswith(bytes([0x14, 0x00, 0x00, 0x00])): return 'type1'
    if data.startswith(bytes([0x04, 0x00, 0x00, 0x00])): return 'type2'
    if data.startswith(bytes([0x00, 0x01, 0x00, 0x00])): return 'type3'
    if data.startswith(b'VANT'): return 'vant'
    if data.startswith(b'MDMP'): return 'mdmp'
    if data.startswith(b'RGIS'): return 'gis'
    if data.startswith(b'NTRK'): return 'ntrk'
    if data.startswith(b'RIFF'): return 'riff'
    if data.startswith(b'BKHD'): return 'bnk'

    # 对于较小的文本类文件，进行内容特征匹配
    if len(data) < 1000000:
        if any(kw in data for kw in [b'void', b'main(', b'include', b'float', b'technique', b'ifndef']):
            return 'shader'
        if b'?xml' in data: return 'xml'
        if b'import' in data: return 'py'
        if any(kw in data for kw in [b'1000', b'ssh', b'png', b'tga', b'exit']):
            return 'txt'

    return 'dat'


def unpack(input_filepath, output_dir):
    """
    根据新的数据结构解包单个文件，并将其放入指定的输出目录。
    """
    print("-" * 50)
    print(f"开始处理文件: {os.path.basename(input_filepath)}")

    # 在指定的输出目录内，为当前文件创建一个独立的子目录
    base_filename = os.path.basename(input_filepath)
    output_subfolder = os.path.join(output_dir, f"{base_filename}_unpacked")

    # 使用 exist_ok=True，如果目录已存在则不会引发错误
    os.makedirs(output_subfolder, exist_ok=True)

    with open(input_filepath, 'rb') as f:
        # 1. 读取文件头：获取文件总数
        try:
            file_count = read_uint32(f)
            if file_count == 0:
                print("文件中没有文件可供提取。")
                return
        except struct.error:
            print("错误：无法读取文件头。文件可能为空或已损坏。")
            return

        # 2. 读取索引表
        index_table = []
        for _ in range(file_count):
            try:
                file_hash = read_uint32(f)
                offset = read_uint32(f)
                compressed_size = read_uint32(f)
                original_size = read_uint32(f)
                compressed_crc = read_uint32(f)
                index_table.append({
                    "hash": file_hash,
                    "offset": offset,
                    "comp_size": compressed_size,
                    "orig_size": original_size,
                    "crc": compressed_crc
                })
            except struct.error:
                print(f"错误：索引表不完整或已损坏。预期有 {file_count} 个条目，但在读取时出错。")
                return

        print(f"找到 {len(index_table)} 个文件条目。开始提取...")

        # 3. 提取文件数据
        manifest_path = os.path.join(output_subfolder, 'manifest.txt')
        with open(manifest_path, 'w', encoding='utf-8') as manifest:
            for i, item in enumerate(index_table):
                f.seek(item["offset"])
                compressed_data = f.read(item["comp_size"])

                if len(compressed_data) != item["comp_size"]:
                    print(f"警告：文件 {i} ({item['hash']}) 的数据块不完整。跳过。")
                    continue

                try:
                    original_data = zlib.decompress(compressed_data) if item["orig_size"] > 0 else b''
                except zlib.error as e:
                    print(f"错误：文件 {i} ({item['hash']}) zlib解压失败: {e}。跳过。")
                    continue

                ext = get_ext(original_data)
                file_name = f'{i:08d}.{ext}'
                file_path = os.path.join(output_subfolder, file_name)

                # 写入解压后的数据
                with open(file_path, 'wb') as out_file:
                    out_file.write(original_data)

                manifest.write(f'{item["hash"]},{file_name}\n')

    print(f"提取完成！文件已保存至目录: {output_subfolder}")


def main():
    parser = argparse.ArgumentParser(description='通用文件解包工具 - 文件夹批量处理')
    parser.add_argument('input_directory', type=str, help='包含待解包文件的输入文件夹路径。')
    parser.add_argument('output_directory', type=str, help='用于存放所有解包后文件的输出文件夹路径。')
    args = parser.parse_args()

    # 检查输入路径是否存在且为文件夹
    if not os.path.isdir(args.input_directory):
        print(f"错误：输入路径 '{args.input_directory}' 不是一个有效的文件夹。")
        return

    print(f"输入文件夹: {args.input_directory}")
    print(f"输出文件夹: {args.output_directory}")

    # 遍历输入文件夹中的所有项目
    for filename in os.listdir(args.input_directory):
        input_filepath = os.path.join(args.input_directory, filename)

        # 确保处理的是文件而不是子目录
        if os.path.isfile(input_filepath):
            unpack(input_filepath, args.output_directory)
        else:
            print(f"跳过子目录: {filename}")

    print("\n所有文件处理完毕。")


if __name__ == '__main__':
    main()