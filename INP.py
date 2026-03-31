# INP.py
# IDA 插件 - 导出反编译函数、字符串、内存、导入表、导出表、
# 段信息、类型定义、数据定义和指针关系图，供 AI 分析使用
#
# 兼容 IDA 7.x / 8.x / 9.0+
# 合并自 INP.py（广泛兼容版）和 ida-no-mcp.py（扩展导出版）

import os
import sys
import ida_hexrays
import ida_funcs
import ida_nalt
import ida_xref
import ida_segment
import ida_bytes
import ida_entry
import idautils
import idc
import ida_auto
import ida_kernwin
import ida_idaapi
import ida_ida
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import multiprocessing as mp

# ---------------------------------------------------------------------------
# 可选模块检测 - 在旧版 IDA 上优雅降级
# ---------------------------------------------------------------------------

try:
    import ida_undo

    HAS_IDA_UNDO = True
except ImportError:
    HAS_IDA_UNDO = False

try:
    import ida_idp

    HAS_IDA_IDP = True
except ImportError:
    HAS_IDA_IDP = False

try:
    import ida_typeinf

    HAS_IDA_TYPEINF = True
except ImportError:
    HAS_IDA_TYPEINF = False

try:
    import ida_name

    HAS_IDA_NAME = True
except ImportError:
    HAS_IDA_NAME = False

# ---------------------------------------------------------------------------
# IDA API 兼容性适配层
# ---------------------------------------------------------------------------


def _is_code(flags):
    """检查代码标志 - 兼容 IDA 7.x 和 9.0+"""
    try:
        # IDA 9.0+ 推荐 API
        return ida_bytes.is_code(flags)
    except AttributeError:
        # IDA 7.x / 8.x 回退
        return idc.is_code(flags)


def _get_flags(ea):
    """获取地址标志 - 兼容 IDA 7.x 和 9.0+"""
    try:
        return ida_bytes.get_flags(ea)
    except AttributeError:
        return idc.get_full_flags(ea)


def _get_func_name(ea):
    """获取函数名 - 兼容 IDA 7.x 和 9.0+"""
    try:
        name = ida_funcs.get_func_name(ea)
        if name:
            return name
    except AttributeError:
        pass
    return idc.get_func_name(ea) or ""


def _get_name(ea):
    """获取地址处的名称 - 兼容 IDA 7.x 和 9.0+"""
    if HAS_IDA_NAME:
        try:
            return ida_name.get_name(ea) or ""
        except Exception:
            pass
    return idc.get_name(ea, 0) or ""


# ---------------------------------------------------------------------------
# 全局配置
# ---------------------------------------------------------------------------

WORKER_COUNT = max(1, mp.cpu_count() - 1)
TASK_BATCH_SIZE = 50

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def get_worker_count():
    """返回配置的并行工作线程数"""
    return WORKER_COUNT


def get_idb_directory():
    """返回当前 IDB 文件所在目录"""
    idb_path = ida_nalt.get_input_file_path()
    if not idb_path:
        try:
            import ida_loader

            idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        except Exception:
            pass
    return os.path.dirname(idb_path) if idb_path else os.getcwd()


def ensure_dir(path):
    """若目录不存在则创建"""
    if not os.path.exists(path):
        os.makedirs(path)


def clear_undo_buffer():
    """清理 IDA 撤销缓冲区，防止内存膨胀。

    IDA 9.0 已移除专用 API，回退为仅执行 gc。
    旧版本中若 ida_undo.clear_undo_buffer 可用则调用。
    """
    try:
        if HAS_IDA_UNDO and hasattr(ida_undo, "clear_undo_buffer"):
            ida_undo.clear_undo_buffer()
        gc.collect()
    except Exception:
        pass


def disable_undo():
    """禁用撤销功能以降低内存占用（IDA 9.0+ 上为空操作）"""
    try:
        if HAS_IDA_IDP and hasattr(ida_idp, "disable_undo"):
            ida_idp.disable_undo(True)
    except Exception:
        pass


def enable_undo():
    """重新启用撤销功能（IDA 9.0+ 上为空操作）"""
    try:
        if HAS_IDA_IDP and hasattr(ida_idp, "disable_undo"):
            ida_idp.disable_undo(False)
    except Exception:
        pass


def get_callers(func_ea):
    """返回调用 func_ea 的函数起始地址列表（已排序去重）"""
    callers = []
    for ref in idautils.XrefsTo(func_ea, 0):
        if _is_code(_get_flags(ref.frm)):
            caller_func = ida_funcs.get_func(ref.frm)
            if caller_func:
                callers.append(caller_func.start_ea)
    return sorted(list(set(callers)))


def get_callees(func_ea):
    """返回 func_ea 调用的函数地址列表（已排序去重）"""
    callees = []
    func = ida_funcs.get_func(func_ea)
    if not func:
        return callees
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if _is_code(_get_flags(head)):
            for ref in idautils.XrefsFrom(head, 0):
                if ref.type in [ida_xref.fl_CF, ida_xref.fl_CN]:
                    callee_func = ida_funcs.get_func(ref.to)
                    if callee_func:
                        callees.append(callee_func.start_ea)
    return sorted(list(set(callees)))


def format_address_list(addr_list):
    """将地址列表格式化为逗号分隔的十六进制字符串"""
    return ", ".join([hex(addr) for addr in addr_list])


def sanitize_filename(name):
    """去除非法文件名字符并截断至 200 个字符"""
    for char in '<>:"/\\|?*':
        name = name.replace(char, "_")
    name = name.replace(".", "_")
    return name[:200] if len(name) > 200 else name


def save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs):
    """将导出进度持久化到 .export_progress，以便崩溃后续传"""
    progress_file = os.path.join(export_dir, ".export_progress")
    try:
        with open(progress_file, "w", encoding="utf-8") as f:
            f.write("# Export Progress\n")
            f.write("# Format: address | status (done/failed/skipped)\n")
            for addr in processed_addrs:
                f.write("{:X}|done\n".format(addr))
            for addr, name, reason in failed_funcs:
                f.write("{:X}|failed|{}|{}\n".format(addr, name, reason))
            for addr, name, reason in skipped_funcs:
                f.write("{:X}|skipped|{}|{}\n".format(addr, name, reason))
    except Exception as e:
        print("[!] Failed to save progress: {}".format(str(e)))


def load_progress(export_dir):
    """加载之前保存的导出进度，返回 (processed_set, failed_list, skipped_list)"""
    progress_file = os.path.join(export_dir, ".export_progress")
    processed = set()
    failed = []
    skipped = []

    if not os.path.exists(progress_file):
        return processed, failed, skipped

    try:
        with open(progress_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) >= 2:
                    addr = int(parts[0], 16)
                    status = parts[1]
                    if status == "done":
                        processed.add(addr)
                    elif status == "failed" and len(parts) >= 4:
                        failed.append((addr, parts[2], parts[3]))
                    elif status == "skipped" and len(parts) >= 4:
                        skipped.append((addr, parts[2], parts[3]))
        print(
            "[+] Loaded progress: {} functions already processed".format(len(processed))
        )
    except Exception as e:
        print("[!] Failed to load progress: {}".format(str(e)))

    return processed, failed, skipped


# ---------------------------------------------------------------------------
# 导出：段信息
# ---------------------------------------------------------------------------


def export_segments(export_dir):
    """将段表导出到 segments.txt

    格式：index|name|start|end|size|perms|type
    """
    segments_path = os.path.join(export_dir, "segments.txt")
    segment_count = 0

    with open(segments_path, "w", encoding="utf-8") as f:
        f.write("# Segments\n")
        f.write("# Format: index|name|start|end|size|perms|type\n")
        f.write("#" + "=" * 60 + "\n\n")

        seg_qty = ida_segment.get_segm_qty()
        for i in range(seg_qty):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue

            seg_name = ida_segment.get_segm_name(seg)
            seg_start = seg.start_ea
            seg_end = seg.end_ea
            seg_size = seg_end - seg_start
            seg_perm = seg.perm

            perms = []
            if seg_perm & 1:
                perms.append("R")
            if seg_perm & 2:
                perms.append("W")
            if seg_perm & 4:
                perms.append("X")
            perm_str = "".join(perms) if perms else "-"

            f.write(
                "{}|{}|{}|{}|{}|{}|{}\n".format(
                    i,
                    seg_name,
                    hex(seg_start),
                    hex(seg_end),
                    seg_size,
                    perm_str,
                    seg.type,
                )
            )
            segment_count += 1

    print("[*] Segments Summary:")
    print("    Total segments: {}".format(segment_count))
    return segment_count


# ---------------------------------------------------------------------------
# 导出：类型定义（结构体、联合体、枚举）
# ---------------------------------------------------------------------------


def export_type_definitions(export_dir):
    """将结构体/联合体/枚举类型定义导出到 type_definitions.txt

    需要 ida_typeinf（IDA 7.2+），旧版本上自动跳过。

    格式：
        S|name|size          （结构体）
        U|name|size          （联合体）
          member|type|offset|size
        E|name               （枚举）
          member=value
    """
    if not HAS_IDA_TYPEINF:
        print("[*] Type Definitions: skipped (ida_typeinf not available)")
        return

    type_path = os.path.join(export_dir, "type_definitions.txt")
    struct_count = 0
    enum_count = 0

    with open(type_path, "w", encoding="utf-8") as f:
        f.write("# Type Definitions (structs, unions, enums)\n")
        f.write("#" + "=" * 60 + "\n\n")

        # --- 结构体和联合体 ---
        tif = ida_typeinf.tinfo_t()
        ordinal = 1
        while True:
            try:
                if not tif.get_numbered_type(None, ordinal):
                    break
            except Exception:
                break

            try:
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    tif.get_udt_details(udt_data)

                    type_kind = "U" if tif.is_union() else "S"
                    try:
                        type_name = ida_typeinf.get_tid_name(tif.get_tid()) or "?"
                    except Exception:
                        type_name = "?"

                    try:
                        type_size = tif.get_size()
                    except Exception:
                        type_size = 0

                    f.write("{}|{}|{}\n".format(type_kind, type_name, type_size))

                    for udm in udt_data:
                        member_name = udm.name if udm.name else ""
                        try:
                            member_type_str = udm.type._print() if udm.type else "?"
                        except Exception:
                            member_type_str = "?"
                        f.write(
                            "  {}|{}|{}|{}\n".format(
                                member_name, member_type_str, udm.offset, udm.size
                            )
                        )

                    if tif.is_union():
                        enum_count += 1
                    else:
                        struct_count += 1
            except Exception:
                pass

            ordinal += 1

        f.write("\n")

        # --- 枚举 ---
        ordinal = 1
        while True:
            tif = ida_typeinf.tinfo_t()
            try:
                if not tif.get_numbered_type(None, ordinal):
                    break
            except Exception:
                break

            try:
                if tif.is_enum():
                    try:
                        type_name = ida_typeinf.get_tid_name(tif.get_tid()) or "?"
                    except Exception:
                        type_name = "?"

                    f.write("E|{}\n".format(type_name))

                    try:
                        edm = ida_typeinf.edm_t()
                        idx = 0
                        while tif.get_edm(edm, idx):
                            f.write(
                                "  {}={}\n".format(
                                    edm.name if edm.name else "?", edm.value
                                )
                            )
                            idx += 1
                    except Exception:
                        pass

                    enum_count += 1
            except Exception:
                pass

            ordinal += 1

    print("[*] Type Definitions Summary:")
    print("    Structs/Unions: {}, Enums: {}".format(struct_count, enum_count))


# ---------------------------------------------------------------------------
# 导出：数据项定义
# ---------------------------------------------------------------------------


def _classify_data_item(addr, flags):
    """解析单个数据地址的类型、大小和值字符串，返回 (size, type_name, value_str)"""
    if ida_bytes.is_byte(flags):
        return 1, "b", "0x{:02X}".format(ida_bytes.get_byte(addr))
    elif ida_bytes.is_word(flags):
        return 2, "w", "0x{:04X}".format(ida_bytes.get_word(addr))
    elif ida_bytes.is_dword(flags):
        return 4, "dw", "0x{:08X}".format(ida_bytes.get_dword(addr))
    elif ida_bytes.is_qword(flags):
        return 8, "qw", "0x{:016X}".format(ida_bytes.get_qword(addr))
    elif ida_bytes.is_oword(flags):
        return 16, "ow", ""
    elif ida_bytes.is_float(flags):
        try:
            import struct as _struct

            value_str = str(
                _struct.unpack("f", _struct.pack("I", ida_bytes.get_dword(addr)))[0]
            )
        except Exception:
            value_str = ""
        return 4, "f", value_str
    elif ida_bytes.is_double(flags):
        try:
            import struct as _struct

            value_str = str(
                _struct.unpack("d", _struct.pack("Q", ida_bytes.get_qword(addr)))[0]
            )
        except Exception:
            value_str = ""
        return 8, "d", value_str
    elif ida_bytes.is_strlit(flags):
        try:
            str_type = idc.get_str_type(addr)
        except Exception:
            str_type = ida_nalt.STRTYPE_C
        if str_type == ida_nalt.STRTYPE_C_16:
            size = ida_bytes.get_max_strlit_length(addr, ida_nalt.STRTYPE_C_16) + 2
            type_name = "wstr"
        else:
            size = ida_bytes.get_max_strlit_length(addr, ida_nalt.STRTYPE_C) + 1
            type_name = "str"
        try:
            raw = ida_bytes.get_strlit_contents(addr, -1, str_type)
            value_str = repr(raw.decode("utf-8", errors="replace")) if raw else ""
        except Exception:
            value_str = ""
        return max(1, size), type_name, value_str
    elif ida_bytes.is_struct(flags):
        try:
            tid = ida_nalt.get_strid(addr)
            if tid != ida_idaapi.BADADDR and HAS_IDA_TYPEINF:
                type_name = ida_typeinf.get_tid_name(tid) or "struct"
                type_tif = ida_typeinf.tinfo_t()
                size = (
                    type_tif.get_size()
                    if type_tif.get_type_by_tid(tid)
                    else ida_bytes.get_data_elsize(addr, flags)
                )
            else:
                type_name = "struct"
                size = ida_bytes.get_data_elsize(addr, flags)
        except Exception:
            type_name = "struct"
            size = ida_bytes.get_data_elsize(addr, flags)
        return max(1, size), type_name, ""
    elif ida_bytes.is_align(flags):
        return max(1, ida_bytes.get_data_elsize(addr, flags)), "align", ""
    else:
        return max(1, ida_bytes.get_data_elsize(addr, flags)), "?", ""


def export_data_definitions(export_dir):
    """将所有命名数据项导出到 data_definitions.txt

    采用双轨策略，确保不遗漏任何命名符号：
      轨道1 - 段遍历：按地址顺序扫描各段，导出所有被 IDA 标记为 data 的项
      轨道2 - 名称表遍历：通过 idautils.Names() 枚举全库命名地址，
              补充轨道1中未覆盖到的命名符号（如 lea 指令引用的 _axpdesc_root
              等未被明确定义为数据的地址）

    格式：address|size|type|name|value
    """
    data_path = os.path.join(export_dir, "data_definitions.txt")
    data_count = 0

    # 记录已通过轨道1导出的地址，供轨道2去重
    exported_addrs = set()

    with open(data_path, "w", encoding="utf-8") as f:
        f.write("# Data Definitions\n")
        f.write("# Format: address|size|type|name|value\n")
        f.write(
            "# Types: b=byte w=word dw=dword qw=qword ow=oword f=float d=double str=string wstr=wstring struct align unk=unnamed/untyped\n"
        )
        f.write("#" + "=" * 60 + "\n\n")

        # ------------------------------------------------------------------
        # 轨道1：按段顺序遍历所有 data head
        # ------------------------------------------------------------------
        seg_qty = ida_segment.get_segm_qty()
        for seg_idx in range(seg_qty):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            seg_start = seg.start_ea
            seg_end = seg.end_ea

            addr = seg_start
            while addr < seg_end:
                try:
                    flags = _get_flags(addr)
                    if ida_bytes.is_data(flags):
                        name = _get_name(addr)
                        size, type_name, value_str = _classify_data_item(addr, flags)
                        f.write(
                            "{}|{}|{}|{}|{}\n".format(
                                hex(addr), size, type_name, name, value_str
                            )
                        )
                        data_count += 1
                        exported_addrs.add(addr)
                        addr += size
                    else:
                        next_addr = idc.next_head(addr, seg_end)
                        addr = next_addr if next_addr > addr else addr + 1
                except Exception:
                    addr += 1

        # ------------------------------------------------------------------
        # 轨道2：遍历全库名称表，补充未被轨道1覆盖的命名地址
        # 典型场景：lea/mov 等指令直接引用的数据地址，IDA 自动命名但未定义为 data
        # ------------------------------------------------------------------
        f.write("\n# --- 命名地址补充（由名称表遍历发现，轨道1未覆盖）---\n\n")
        named_count = 0
        for addr, name in idautils.Names():
            if addr in exported_addrs:
                continue  # 轨道1已导出，跳过
            try:
                flags = _get_flags(addr)
                # 跳过代码地址（函数/指令），只关心数据/未知区域
                if _is_code(flags) or ida_funcs.get_func(addr) is not None:
                    continue
                if ida_bytes.is_data(flags):
                    # 有 data 标志但轨道1未到达（跨段或对齐跳过），按正常类型处理
                    size, type_name, value_str = _classify_data_item(addr, flags)
                else:
                    # 未定义类型：读取指针大小的值（最常见的场景是指针符号）
                    # 根据当前二进制位宽决定读取宽度
                    import ida_ida as _ida_ida

                    ptr_size = 8 if _ida_ida.inf_is_64bit() else 4
                    if ptr_size == 8:
                        value = ida_bytes.get_qword(addr)
                        value_str = "0x{:016X}".format(value)
                        type_name = "qw"
                    else:
                        value = ida_bytes.get_dword(addr)
                        value_str = "0x{:08X}".format(value)
                        type_name = "dw"
                    size = ptr_size
                f.write(
                    "{}|{}|{}|{}|{}\n".format(
                        hex(addr), size, type_name, name, value_str
                    )
                )
                data_count += 1
                named_count += 1
            except Exception:
                continue

    print("[*] Data Definitions Summary:")
    print("    Total data items: {}".format(data_count))
    print("    - Segment scan:  {}".format(data_count - named_count))
    print("    - Names table:   {}".format(named_count))
    return data_count


# ---------------------------------------------------------------------------
# 导出：指针关系图
# ---------------------------------------------------------------------------


def export_pointer_graph(export_dir):
    """将数据段中的指针关系导出到 pointer_graph.txt

    格式：source|target|target_name|target_type|pNN
      target_type: F=函数, C=代码, D=数据, ?=未知
      pNN: 指针宽度（位），如 p16/p32/p64
    """
    pointer_path = os.path.join(export_dir, "pointer_graph.txt")
    pointer_count = 0

    with open(pointer_path, "w", encoding="utf-8") as f:
        f.write("# Pointer Graph\n")
        f.write("# Format: source|target|target_name|target_type|ptr_width\n")
        f.write("# target_type: F=function C=code D=data ?=unknown\n")
        f.write("#" + "=" * 60 + "\n\n")

        seg_qty = ida_segment.get_segm_qty()

        for seg_idx in range(seg_qty):
            seg = ida_segment.getnseg(seg_idx)
            if seg is None:
                continue

            seg_start = seg.start_ea
            seg_end = seg.end_ea

            addr = seg_start
            while addr < seg_end:
                try:
                    flags = _get_flags(addr)

                    if ida_bytes.is_data(flags):
                        ptr_size = 0
                        if ida_bytes.is_word(flags):
                            ptr_size = 2
                        elif ida_bytes.is_dword(flags):
                            ptr_size = 4
                        elif ida_bytes.is_qword(flags):
                            ptr_size = 8

                        if ptr_size > 0:
                            if ptr_size == 2:
                                ptr_value = ida_bytes.get_word(addr)
                            elif ptr_size == 4:
                                ptr_value = ida_bytes.get_dword(addr)
                            else:
                                ptr_value = ida_bytes.get_qword(addr)

                            if ptr_value != 0:
                                target_name = _get_name(ptr_value)

                                target_func = ida_funcs.get_func(ptr_value)
                                if target_func:
                                    target_type = "F"
                                else:
                                    target_flags = _get_flags(ptr_value)
                                    if _is_code(target_flags):
                                        target_type = "C"
                                    elif ida_bytes.is_data(target_flags):
                                        target_type = "D"
                                    else:
                                        target_type = "?"

                                f.write(
                                    "{}|{}|{}|{}|p{}\n".format(
                                        hex(addr),
                                        hex(ptr_value),
                                        target_name,
                                        target_type,
                                        ptr_size * 8,
                                    )
                                )
                                pointer_count += 1

                            addr += ptr_size
                        else:
                            next_addr = idc.next_head(addr, seg_end)
                            addr = next_addr if next_addr > addr else addr + 1
                    else:
                        next_addr = idc.next_head(addr, seg_end)
                        addr = next_addr if next_addr > addr else addr + 1
                except Exception:
                    addr += 1

    print("[*] Pointer Graph Summary:")
    print("    Total pointers: {}".format(pointer_count))
    return pointer_count


# ---------------------------------------------------------------------------
# 导出：字符串
# ---------------------------------------------------------------------------


def export_strings(export_dir):
    """将所有字符串导出到 strings.txt

    格式：address | length | type | string
    字符串类型：ASCII, UTF-16, UTF-32
    """
    strings_path = os.path.join(export_dir, "strings.txt")
    string_count = 0
    BATCH_SIZE = 500

    with open(strings_path, "w", encoding="utf-8") as f:
        f.write("# Strings exported from IDA\n")
        f.write("# Format: address | length | type | string\n")
        f.write("#" + "=" * 80 + "\n\n")

        for idx, s in enumerate(idautils.Strings()):
            try:
                string_content = str(s)
                if s.strtype == ida_nalt.STRTYPE_C_16:
                    str_type = "UTF-16"
                elif s.strtype == ida_nalt.STRTYPE_C_32:
                    str_type = "UTF-32"
                else:
                    str_type = "ASCII"

                f.write(
                    "{} | {} | {} | {}\n".format(
                        hex(s.ea),
                        s.length,
                        str_type,
                        string_content.replace("\n", "\\n").replace("\r", "\\r"),
                    )
                )
                string_count += 1

                if (idx + 1) % BATCH_SIZE == 0:
                    clear_undo_buffer()
            except Exception:
                continue

    print("[*] Strings Summary:")
    print("    Total strings: {}".format(string_count))


# ---------------------------------------------------------------------------
# 导出：导入表
# ---------------------------------------------------------------------------


def export_imports(export_dir):
    """将导入表导出到 imports.txt

    格式：address:name（无名称时为 address:ordinal_N）
    """
    imports_path = os.path.join(export_dir, "imports.txt")
    import_count = 0

    with open(imports_path, "w", encoding="utf-8") as f:
        f.write("# Imports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")

        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)

            def imp_cb(ea, name, ordinal):
                nonlocal import_count
                if name:
                    f.write("{}:{}\n".format(hex(ea), name))
                else:
                    f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
                import_count += 1
                return True

            ida_nalt.enum_import_names(i, imp_cb)

    print("[*] Imports Summary:")
    print("    Total imports: {}".format(import_count))


# ---------------------------------------------------------------------------
# 导出：导出表
# ---------------------------------------------------------------------------


def export_exports(export_dir):
    """将导出表导出到 exports.txt

    格式：address:name（无名称时为 address:ordinal_N）
    """
    exports_path = os.path.join(export_dir, "exports.txt")
    export_count = 0

    with open(exports_path, "w", encoding="utf-8") as f:
        f.write("# Exports\n")
        f.write("# Format: func-addr:func-name\n")
        f.write("#" + "=" * 60 + "\n\n")

        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal)

            if name:
                f.write("{}:{}\n".format(hex(ea), name))
            else:
                f.write("{}:ordinal_{}\n".format(hex(ea), ordinal))
            export_count += 1

    print("[*] Exports Summary:")
    print("    Total exports: {}".format(export_count))


# ---------------------------------------------------------------------------
# 导出：内存 hexdump
# ---------------------------------------------------------------------------


def export_memory(export_dir):
    """将原始内存按 1MB 分块导出为 hexdump 文件，保存在 memory/ 目录下

    每行格式：Address | Hex bytes | ASCII
    """
    memory_dir = os.path.join(export_dir, "memory")
    ensure_dir(memory_dir)

    CHUNK_SIZE = 1 * 1024 * 1024  # 每块 1MB
    BYTES_PER_LINE = 16

    total_bytes = 0
    file_count = 0

    for seg_idx in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(seg_idx)
        if seg is None:
            continue

        seg_start = seg.start_ea
        seg_end = seg.end_ea
        seg_name = ida_segment.get_segm_name(seg)

        print(
            "[*] Processing segment: {} ({} - {})".format(
                seg_name, hex(seg_start), hex(seg_end)
            )
        )

        current_addr = seg_start
        while current_addr < seg_end:
            chunk_end = min(current_addr + CHUNK_SIZE, seg_end)

            filename = "{:08X}--{:08X}.txt".format(current_addr, chunk_end)
            filepath = os.path.join(memory_dir, filename)

            # 续传支持：跳过已写入的块
            if os.path.exists(filepath):
                file_count += 1
                current_addr = chunk_end
                continue

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(
                    "# Memory dump: {} - {}\n".format(hex(current_addr), hex(chunk_end))
                )
                f.write("# Segment: {}\n".format(seg_name))
                f.write("#" + "=" * 76 + "\n\n")
                f.write(
                    "# Address        | Hex Bytes                                       | ASCII\n"
                )
                f.write("#" + "-" * 76 + "\n")

                addr = current_addr
                while addr < chunk_end:
                    line_bytes = []
                    for i in range(BYTES_PER_LINE):
                        if addr + i < chunk_end:
                            byte_val = ida_bytes.get_byte(addr + i)
                            line_bytes.append(byte_val if byte_val is not None else 0)
                        else:
                            break

                    if not line_bytes:
                        addr += BYTES_PER_LINE
                        continue

                    hex_part = ""
                    for i, b in enumerate(line_bytes):
                        hex_part += "{:02X} ".format(b)
                        if i == 7:
                            hex_part += " "
                    remaining = BYTES_PER_LINE - len(line_bytes)
                    if remaining > 0:
                        if len(line_bytes) <= 8:
                            hex_part += " "
                        hex_part += "   " * remaining

                    ascii_part = "".join(
                        chr(b) if 0x20 <= b <= 0x7E else "." for b in line_bytes
                    )

                    f.write(
                        "{:016X} | {} | {}\n".format(
                            addr, hex_part.ljust(49), ascii_part
                        )
                    )

                    addr += BYTES_PER_LINE
                    total_bytes += len(line_bytes)

            file_count += 1
            current_addr = chunk_end
            clear_undo_buffer()

    print("\n[*] Memory Export Summary:")
    print(
        "    Total bytes: {} ({:.2f} MB)".format(
            total_bytes, total_bytes / (1024 * 1024)
        )
    )
    print("    Files created: {}".format(file_count))


# ---------------------------------------------------------------------------
# 导出：反编译函数
# ---------------------------------------------------------------------------


def export_decompiled_functions(export_dir, skip_existing=True):
    """将所有反编译函数导出为独立 .c 文件，保存在 decompile/ 目录下

    内存优化模式：流式处理、单线程 I/O、激进 GC。
    通过 .export_progress 支持崩溃续传。

    每个文件包含头部注释：
        /* func-name, func-address, callers, callees */
    """
    decompile_dir = os.path.join(export_dir, "decompile")
    ensure_dir(decompile_dir)

    total_funcs = 0
    exported_funcs = 0
    failed_funcs = []
    skipped_funcs = []
    function_index = []
    addr_to_info = {}

    io_executor = ThreadPoolExecutor(max_workers=1)

    processed_addrs, prev_failed, prev_skipped = load_progress(export_dir)
    failed_funcs.extend(prev_failed)
    skipped_funcs.extend(prev_skipped)

    all_funcs = list(idautils.Functions())
    total_funcs = len(all_funcs)
    remaining_funcs = [ea for ea in all_funcs if ea not in processed_addrs]

    print(
        "[*] Found {} functions total, {} remaining to process".format(
            total_funcs, len(remaining_funcs)
        )
    )
    print("[*] Memory-optimized mode: processing one function at a time")

    if not remaining_funcs:
        print("[+] All functions already exported!")
        io_executor.shutdown(wait=False)
        return

    BATCH_SIZE = 10
    MEMORY_CLEAN_INTERVAL = 5
    pending_writes = []

    def write_function_file(args):
        func_ea, func_name, dec_str, callers, callees = args
        output_lines = [
            "/*",
            " * func-name: {}".format(func_name),
            " * func-address: {}".format(hex(func_ea)),
            " * callers: {}".format(
                format_address_list(callers) if callers else "none"
            ),
            " * callees: {}".format(
                format_address_list(callees) if callees else "none"
            ),
            " */",
            "",
            dec_str,
        ]
        output_filename = "{:X}.c".format(func_ea)
        output_path = os.path.join(decompile_dir, output_filename)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("\n".join(output_lines))
            return func_ea, func_name, True, output_filename, callers, callees, None
        except IOError as e:
            return func_ea, func_name, False, output_filename, callers, callees, str(e)

    def aggressive_memory_cleanup():
        try:
            if hasattr(ida_hexrays, "clear_cached_cfuncs"):
                ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass
        gc.collect()
        gc.collect()

    def flush_pending(pending):
        """等待待处理的写入 future 并收集结果"""
        nonlocal exported_funcs
        for future, fea, fname, ofilename, fcallers, fcallees in pending:
            try:
                result = future.result()
                r_ea, r_name, success, r_file, r_callers, r_callees, error = result
                if success:
                    info = {
                        "address": r_ea,
                        "name": r_name,
                        "filename": r_file,
                        "callers": r_callers,
                        "callees": r_callees,
                    }
                    function_index.append(info)
                    addr_to_info[r_ea] = info
                    exported_funcs += 1
                    processed_addrs.add(r_ea)
                else:
                    failed_funcs.append((r_ea, r_name, "IO error: {}".format(error)))
                    processed_addrs.add(r_ea)
            except Exception as e:
                print("[!] Write error: {}".format(str(e)))

    for idx, func_ea in enumerate(remaining_funcs):
        func_name = _get_func_name(func_ea)

        func = ida_funcs.get_func(func_ea)
        if func is None:
            skipped_funcs.append((func_ea, func_name, "not a valid function"))
            processed_addrs.add(func_ea)
            continue

        if func.flags & ida_funcs.FUNC_LIB:
            skipped_funcs.append((func_ea, func_name, "library function"))
            processed_addrs.add(func_ea)
            continue

        dec_str = None
        dec_obj = None

        try:
            dec_obj = ida_hexrays.decompile(func_ea)
            if dec_obj is None:
                failed_funcs.append((func_ea, func_name, "decompile returned None"))
                processed_addrs.add(func_ea)
                continue

            dec_str = str(dec_obj)
            dec_obj = None

            if not dec_str or not dec_str.strip():
                failed_funcs.append((func_ea, func_name, "empty decompilation result"))
                processed_addrs.add(func_ea)
                continue

            callers = get_callers(func_ea)
            callees = get_callees(func_ea)

            output_filename = "{:X}.c".format(func_ea)
            output_path = os.path.join(decompile_dir, output_filename)

            if skip_existing and os.path.exists(output_path):
                exported_funcs += 1
                processed_addrs.add(func_ea)
                dec_str = None
                if (exported_funcs + len(prev_failed) + len(prev_skipped)) % 100 == 0:
                    print(
                        "[+] Exported {} / {} functions...".format(
                            exported_funcs + len(prev_failed) + len(prev_skipped),
                            total_funcs,
                        )
                    )
                continue

            write_args = (func_ea, func_name, dec_str, callers, callees)
            future = io_executor.submit(write_function_file, write_args)
            pending_writes.append(
                (future, func_ea, func_name, output_filename, callers, callees)
            )
            dec_str = None

        except ida_hexrays.DecompilationFailure as e:
            failed_funcs.append(
                (func_ea, func_name, "decompilation failure: {}".format(str(e)))
            )
            processed_addrs.add(func_ea)
            continue
        except Exception as e:
            failed_funcs.append(
                (func_ea, func_name, "unexpected error: {}".format(str(e)))
            )
            print(
                "[!] Error decompiling {} at {}: {}".format(
                    func_name, hex(func_ea), str(e)
                )
            )
            processed_addrs.add(func_ea)
            continue
        finally:
            dec_obj = None
            dec_str = None

        if (idx + 1) % MEMORY_CLEAN_INTERVAL == 0:
            clear_undo_buffer()
            aggressive_memory_cleanup()

        if len(pending_writes) >= BATCH_SIZE:
            flush_pending(pending_writes)
            save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs)
            if exported_funcs % 100 == 0:
                print(
                    "[+] Exported {} / {} functions...".format(
                        exported_funcs + len(prev_failed) + len(prev_skipped),
                        total_funcs,
                    )
                )
            if len(function_index) > 1000:
                function_index.clear()
                addr_to_info.clear()
            pending_writes = []
            aggressive_memory_cleanup()

    # 处理剩余的写入任务
    if pending_writes:
        flush_pending(pending_writes)

    io_executor.shutdown(wait=True)
    save_progress(export_dir, processed_addrs, failed_funcs, skipped_funcs)

    print("\n[*] Decompilation Summary:")
    print("    Total functions: {}".format(total_funcs))
    print("    Exported: {}".format(exported_funcs))
    print("    Skipped: {} (library/invalid)".format(len(skipped_funcs)))
    print("    Failed: {}".format(len(failed_funcs)))

    # 保存失败日志
    if failed_funcs:
        failed_log_path = os.path.join(export_dir, "decompile_failed.txt")
        with open(failed_log_path, "w", encoding="utf-8") as f:
            f.write("# Failed to decompile {} functions\n".format(len(failed_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in failed_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Failed list saved to: decompile_failed.txt")

    # 保存跳过日志
    if skipped_funcs:
        skipped_log_path = os.path.join(export_dir, "decompile_skipped.txt")
        with open(skipped_log_path, "w", encoding="utf-8") as f:
            f.write("# Skipped {} functions\n".format(len(skipped_funcs)))
            f.write("# Format: address | function_name | reason\n")
            f.write("#" + "=" * 80 + "\n\n")
            for addr, name, reason in skipped_funcs:
                f.write("{} | {} | {}\n".format(hex(addr), name, reason))
        print("    Skipped list saved to: decompile_skipped.txt")

    # 生成函数索引文件
    if function_index:
        index_path = os.path.join(export_dir, "function_index.txt")
        with open(index_path, "w", encoding="utf-8") as f:
            f.write("# Function Index\n")
            f.write("# Total exported functions: {}\n".format(len(function_index)))
            f.write("#" + "=" * 80 + "\n\n")

            for func_info in function_index:
                f.write("=" * 80 + "\n")
                f.write("Function: {}\n".format(func_info["name"]))
                f.write("Address:  {}\n".format(hex(func_info["address"])))
                f.write("File:     {}\n".format(func_info["filename"]))
                f.write("\n")

                if func_info["callers"]:
                    f.write(
                        "Called by ({} callers):\n".format(len(func_info["callers"]))
                    )
                    for caller_addr in func_info["callers"]:
                        if caller_addr in addr_to_info:
                            ci = addr_to_info[caller_addr]
                            f.write(
                                "  - {} ({}) -> {}\n".format(
                                    hex(caller_addr), ci["name"], ci["filename"]
                                )
                            )
                        else:
                            f.write(
                                "  - {} ({})\n".format(
                                    hex(caller_addr), _get_func_name(caller_addr)
                                )
                            )
                else:
                    f.write("Called by: none\n")

                f.write("\n")

                if func_info["callees"]:
                    f.write("Calls ({} callees):\n".format(len(func_info["callees"])))
                    for callee_addr in func_info["callees"]:
                        if callee_addr in addr_to_info:
                            ci = addr_to_info[callee_addr]
                            f.write(
                                "  - {} ({}) -> {}\n".format(
                                    hex(callee_addr), ci["name"], ci["filename"]
                                )
                            )
                        else:
                            f.write(
                                "  - {} ({})\n".format(
                                    hex(callee_addr), _get_func_name(callee_addr)
                                )
                            )
                else:
                    f.write("Calls: none\n")

                f.write("\n")

        print("    Function index saved to: function_index.txt")


# ---------------------------------------------------------------------------
# 主导出流程
# ---------------------------------------------------------------------------


def do_export(
    export_dir=None, ask_user=True, skip_auto_analysis=False, worker_count=None
):
    """执行完整的导出流程。

    参数：
        export_dir:          目标目录，None 表示自动检测或询问用户。
        ask_user:            为 True 时弹出目录选择对话框。
        skip_auto_analysis:  为 True 时跳过 ida_auto.auto_wait()。
        worker_count:        覆盖 WORKER_COUNT（None 表示使用默认值）。
    """
    global WORKER_COUNT

    if worker_count is not None:
        WORKER_COUNT = max(1, worker_count)

    print("=" * 60)
    print("IDA Export for AI Analysis")
    print("=" * 60)
    print("[*] Using {} worker threads for parallel I/O".format(WORKER_COUNT))

    # IDA 兼容性提示
    if not HAS_IDA_TYPEINF:
        print(
            "[!] ida_typeinf not available - type/data/pointer exports will be skipped"
        )
    if not HAS_IDA_NAME:
        print("[!] ida_name not available - falling back to idc.get_name()")

    clear_undo_buffer()
    disable_undo()

    if not ida_hexrays.init_hexrays_plugin():
        print("[!] Hex-Rays decompiler is not available!")
        print("[!] Strings/memory/etc. will still be exported, but no decompilation.")
        has_hexrays = False
    else:
        has_hexrays = True
        print("[+] Hex-Rays decompiler initialized")

    if not skip_auto_analysis:
        print("[*] Waiting for auto-analysis to complete...")
        print("[*] Tip: For large files this may take a while.")
        clear_undo_buffer()
        ida_auto.auto_wait()
        clear_undo_buffer()
    else:
        print("[*] Skipping auto-analysis wait (assuming already complete)")

    # 确定导出目录
    if export_dir is None:
        idb_dir = get_idb_directory()
        default_export_dir = os.path.join(idb_dir, "export-for-ai")

        if ask_user:
            choice = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                "Export to default directory?\n\n{}\n\n"
                "Yes: Use default directory\n"
                "No: Choose custom directory\n"
                "Cancel: Abort export".format(default_export_dir),
            )

            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                enable_undo()
                return
            elif choice == ida_kernwin.ASKBTN_NO:
                selected_dir = ida_kernwin.ask_str(
                    default_export_dir, 0, "Enter export directory path:"
                )
                if selected_dir:
                    export_dir = selected_dir
                    print("[*] Using custom directory: {}".format(export_dir))
                else:
                    print("[*] Export cancelled by user")
                    enable_undo()
                    return
            else:
                export_dir = default_export_dir
        else:
            export_dir = default_export_dir

    ensure_dir(export_dir)
    print("[+] Export directory: {}".format(export_dir))
    print("")

    # --- 导出流程 ---

    print("[*] Exporting segments...")
    export_segments(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting type definitions...")
    export_type_definitions(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting data definitions...")
    export_data_definitions(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting pointer graph...")
    export_pointer_graph(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting strings...")
    export_strings(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting imports...")
    export_imports(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting exports...")
    export_exports(export_dir)
    clear_undo_buffer()
    print("")

    print("[*] Exporting memory...")
    export_memory(export_dir)
    clear_undo_buffer()
    print("")

    if has_hexrays:
        print("[*] Exporting decompiled functions...")
        print(
            "[*] Tip: If IDA crashes, restart and the export will resume from where it left off"
        )
        export_decompiled_functions(export_dir, skip_existing=True)

    enable_undo()

    print("")
    print("=" * 60)
    print("[+] Export completed!")
    print("    Output directory: {}".format(export_dir))
    print("=" * 60)

    ida_kernwin.info("Export completed!\n\nOutput directory:\n{}".format(export_dir))


# ---------------------------------------------------------------------------
# 插件类
# ---------------------------------------------------------------------------


class ExportForAIPlugin(ida_idaapi.plugin_t):
    """IDA 插件，将二进制分析数据导出供 AI 使用"""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Export IDA data for AI analysis"
    help = (
        "Export decompiled functions, strings, memory, imports, exports, "
        "segments, type definitions, data definitions and pointer graph"
    )
    wanted_name = "Export for AI"
    wanted_hotkey = "Ctrl-Shift-E"

    def init(self):
        print("[+] Export for AI plugin loaded")
        print("    Hotkey: {}".format(self.wanted_hotkey))
        print("    Menu: Edit -> Plugins -> Export for AI")
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            choice = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                "Has the auto-analysis already completed?\n\n"
                "Yes: Skip waiting for auto-analysis (faster)\n"
                "No: Wait for auto-analysis to complete\n"
                "Cancel: Abort export",
            )

            if choice == ida_kernwin.ASKBTN_CANCEL:
                print("[*] Export cancelled by user")
                return

            skip_analysis = choice == ida_kernwin.ASKBTN_YES
            do_export(skip_auto_analysis=skip_analysis)
        except Exception as e:
            print("[!] Export failed: {}".format(str(e)))
            import traceback

            traceback.print_exc()
            ida_kernwin.warning("Export failed!\n\n{}".format(str(e)))

    def term(self):
        print("[-] Export for AI plugin unloaded")


def PLUGIN_ENTRY():
    """IDA 插件入口点"""
    return ExportForAIPlugin()


# ---------------------------------------------------------------------------
# 独立脚本支持（批处理 / 无头模式）
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    export_dir = None
    skip_analysis = False

    try:
        # IDA 9.0+ 推荐 API
        if hasattr(idc, "ARGV") and idc.ARGV is not None and len(idc.ARGV) > 1:
            export_dir = idc.ARGV[1]
            if len(idc.ARGV) > 2:
                skip_analysis = idc.ARGV[2] == "1"
        else:
            # 旧版 IDA 回退方式
            argc = int(idc.eval_idc("ARGV.count"))
            if argc >= 2:
                export_dir = idc.eval_idc("ARGV[1]")
            if argc >= 3:
                skip_analysis = idc.eval_idc("ARGV[2]") == "1"
    except Exception:
        pass

    do_export(export_dir, ask_user=False, skip_auto_analysis=skip_analysis)

    print("[*] Script execution completed, exiting IDA...")
    idc.qexit(0)
