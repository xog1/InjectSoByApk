import os
import shutil
import subprocess
from pathlib import Path
import lief


class ApkModifierError(Exception):
    pass


def _run_cmd(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise ApkModifierError(
            f"命令执行失败: {cmd}\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result.stdout


def inject_and_sign(
        apk_path: str,
        injections: dict,
        hook_so_dir: str = "input_libs",
        output_dir: str = "output_apk",
        output_apk_name: str = "mod_final_signed.apk",
        unpacked_dir: str = "unpacked_dir",
        # 核心改进：允许自定义工具路径，默认自动绑定到本库所在目录下的 jar 包
        apktool_path: str = None,
        signer_path: str = None,
        ks_path: str = None,
        ks_pass: str = None,
        ks_alias: str = None,
        cleanup: bool = True
) -> str:
    """
    通用 APK 动态注入与签名函数（路径自适应版）。

    所有中间产物/签名产物均使用绝对路径定位，不再依赖调用方的当前工作目录。
    """
    # 获取当前 py 文件所在的绝对目录（即工具库的根目录）
    lib_root = Path(__file__).resolve().parent

    # 如果未指定工具路径，默认使用工具库同级目录下的 jar 包
    if not apktool_path:
        apktool_path = str(lib_root / "apktool.jar")
    if not signer_path:
        signer_path = str(lib_root / "uber-apk-signer.jar")

    # 校验工具是否存在
    if not Path(apktool_path).exists():
        raise FileNotFoundError(f"找不到 apktool 工具: {apktool_path}")
    if not Path(signer_path).exists():
        raise FileNotFoundError(f"找不到签名工具: {signer_path}")

    apk_file = Path(apk_path)
    if not apk_file.exists():
        raise FileNotFoundError(f"找不到目标 APK 文件: {apk_path}")

    unpacked_path = Path(unpacked_dir).resolve()
    output_unsigned = unpacked_path.parent / "output_unsigned.apk"
    out_dir_path = Path(output_dir).resolve()
    out_dir_path.mkdir(parents=True, exist_ok=True)
    final_output_path = out_dir_path / output_apk_name

    try:
        print(f"[*] 开始解包 APK: {apk_file.name}")
        if unpacked_path.exists():
            shutil.rmtree(unpacked_path)

        # 使用绝对路径执行 apktool
        _run_cmd(f"java -jar \"{apktool_path}\" d \"{apk_path}\" -o \"{unpacked_path}\"")

        print("\n[*] 开始执行多路 .so 依赖注入与文件复制...")
        hook_so_path = Path(hook_so_dir)
        target_lib_root = unpacked_path / "lib"

        if not target_lib_root.exists():
            raise ApkModifierError(f"解包后的 lib 目录不存在: {target_lib_root}")

        for abi_dir in target_lib_root.iterdir():
            if not abi_dir.is_dir():
                continue
            abi_name = abi_dir.name
            print(f" -> 正在处理架构: {abi_name}")

            for target_so_name, hook_so_name in injections.items():
                hook_so_file = hook_so_path / abi_name / hook_so_name
                target_so_file = abi_dir / target_so_name

                if not hook_so_file.exists():
                    print(f"   [跳过] 找不到 Hook 文件: {hook_so_file}")
                    continue

                shutil.copy2(hook_so_file, abi_dir)
                print(f"   [成功] 复制 {hook_so_name} -> {abi_dir}")

                if target_so_file.exists():
                    print(f"   [修改] 向 {target_so_name} 注入依赖: {hook_so_name}")
                    binary = lief.parse(str(target_so_file))
                    if binary:
                        existing_libs = [
                            lib if isinstance(lib, str) else getattr(lib, 'name', str(lib))
                            for lib in binary.libraries
                        ]
                        if hook_so_name not in existing_libs:
                            binary.add_library(hook_so_name)
                            binary.write(str(target_so_file))
                            print(f"   [注入成功]")
                        else:
                            print(f"   [提示] 依赖已存在，跳过。")
                else:
                    print(f"   [警告] 未找到目标宿主 .so: {target_so_file}")

        print("\n[*] 正在重新打包未签名 APK...")
        if output_unsigned.exists():
            output_unsigned.unlink()
        _run_cmd(f"java -jar \"{apktool_path}\" b \"{unpacked_path}\" -o \"{output_unsigned}\"")

        print("\n[*] 正在使用 uber-apk-signer 进行签名与对齐...")
        # 让签名产物直接落在 output_dir 内，并用已经存在的文件集合区分本次产物
        pre_existing = set(out_dir_path.glob("*signed.apk"))
        sign_cmd = (
            f"java -jar \"{signer_path}\" --apks \"{output_unsigned}\" "
            f"--out \"{out_dir_path}\""
        )
        if ks_path and ks_pass and ks_alias:
            sign_cmd += f" --ks \"{ks_path}\" --ksPass \"{ks_pass}\" --ksAlias \"{ks_alias}\""
        _run_cmd(sign_cmd)

        signed_candidates = [
            p for p in out_dir_path.glob("*signed.apk") if p not in pre_existing
        ] or list(out_dir_path.glob("*signed.apk"))
        if not signed_candidates:
            raise ApkModifierError(
                f"签名工具未生成预期的签名 APK 文件（输出目录: {out_dir_path}）。"
            )

        latest_signed = max(signed_candidates, key=os.path.getmtime)
        idsig_path = latest_signed.with_name(latest_signed.name + ".idsig")
        if final_output_path.exists():
            final_output_path.unlink()
        shutil.move(str(latest_signed), str(final_output_path))
        # v4 签名附属文件（.idsig）对被注入的 APK 没有意义，直接删除避免污染 dist
        if idsig_path.exists():
            idsig_path.unlink()

        print(f"\n[+] 处理完成！成品路径: {final_output_path}")
        return str(final_output_path)

    finally:
        if cleanup:
            print("\n[*] 正在清理临时中间文件...")
            if unpacked_path.exists():
                shutil.rmtree(unpacked_path)
            if output_unsigned.exists():
                output_unsigned.unlink()
            for extra_file in out_dir_path.glob("output_unsigned*.apk*"):
                if extra_file.is_file():
                    extra_file.unlink()