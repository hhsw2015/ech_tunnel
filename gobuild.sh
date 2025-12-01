#!/bin/bash

# Go 跨平台编译脚本
# 支持多架构和平台选择，最小化编译，编译后清理选项

# set -e  # 注释掉，允许编译失败时继续

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 支持的平台和架构
PLATFORMS=(
    "android/386" "android/amd64" "android/arm" "android/arm64"
    "darwin/386" "darwin/amd64" "darwin/arm" "darwin/arm64"
    "dragonfly/amd64"
    "freebsd/386" "freebsd/amd64" "freebsd/arm" "freebsd/arm64"
    "linux/386" "linux/amd64" 
    "linux/armv5" "linux/armv6" "linux/armv7" "linux/arm64"
    "linux/mips-hard" "linux/mips-soft" "linux/mips64" 
    "linux/mipsle-hard" "linux/mipsle-soft" "linux/mips64le" 
    "linux/ppc64" "linux/ppc64le" "linux/riscv64" "linux/s390x"
    "netbsd/386" "netbsd/amd64" "netbsd/arm" "netbsd/arm64"
    "openbsd/386" "openbsd/amd64" "openbsd/arm" "openbsd/arm64"
    "plan9/386" "plan9/amd64"
    "solaris/amd64"
    "windows/386" "windows/amd64" "windows/arm" "windows/arm64"
)

# 打印标题
print_title() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}    Go 跨平台编译脚本${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

# 打印平台列表
print_platforms() {
    echo -e "${YELLOW}支持的平台和架构:${NC}"
    echo
    for i in "${!PLATFORMS[@]}"; do
        printf "${GREEN}%2d)${NC} %s\n" $((i+1)) "${PLATFORMS[$i]}"
    done
    echo
}

# 获取编译参数
get_build_params() {
    echo -e "${YELLOW}请输入源文件名 (留空则编译当前目录所有.go文件):${NC}"
    read -r SOURCE_FILE
    
    echo -e "${YELLOW}请输入输出文件名 (默认: main):${NC}"
    read -r OUTPUT_NAME
    
    if [[ -z "$OUTPUT_NAME" ]]; then
        OUTPUT_NAME="main"
    fi
    
    echo -e "${GREEN}源文件: ${SOURCE_FILE:-"所有.go文件"}${NC}"
    echo -e "${GREEN}输出名称: ${OUTPUT_NAME}${NC}"
    echo
}

# 获取用户选择
get_user_choice() {
    while true; do
        echo -e "${YELLOW}请选择编译平台 (输入数字 1-${#PLATFORMS[@]}, 或 'a' 编译所有平台, 'q' 退出):${NC}"
        read -r choice
        
        if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
            echo -e "${RED}退出编译${NC}"
            exit 0
        elif [[ "$choice" == "a" || "$choice" == "A" ]]; then
            return 0
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#PLATFORMS[@]}" ]; then
            SELECTED_PLATFORM="${PLATFORMS[$((choice-1))]}"
            return 1
        else
            echo -e "${RED}无效选择，请重新输入${NC}"
        fi
    done
}

# 编译单个平台
build_single() {
    local platform=$1
    local goos=$(echo "$platform" | cut -d'/' -f1)
    local goarch_full=$(echo "$platform" | cut -d'/' -f2)
    
    # 解析架构和变体
    local goarch="$goarch_full"
    local goarm=""
    local gomips=""
    local arch_suffix="$goarch_full"
    
    # 处理ARM变体
    if [[ "$goarch_full" =~ ^armv([5-8])$ ]]; then
        goarch="arm"
        goarm="${BASH_REMATCH[1]}"
        arch_suffix="armv${goarm}"
    # 处理MIPS变体
    elif [[ "$goarch_full" =~ ^mips(le)?-(hard|soft)$ ]]; then
        if [[ "$goarch_full" == *"le"* ]]; then
            goarch="mipsle"
        else
            goarch="mips"
        fi
        # 转换MIPS变体名称为Go编译器认可的格式
        if [[ "${BASH_REMATCH[2]}" == "hard" ]]; then
            gomips="hardfloat"
        else
            gomips="softfloat"
        fi
        arch_suffix="$goarch_full"
    fi
    
    echo -e "${BLUE}正在编译 ${platform}...${NC}"
    
    # 设置输出文件名
    local output_name="${OUTPUT_NAME}-${goos}-${arch_suffix}"
    if [[ "$goos" == "windows" ]]; then
        output_name="${OUTPUT_NAME}-${goos}-${arch_suffix}.exe"
    fi
    
    # 创建输出目录
    local output_dir="build"
    mkdir -p "$output_dir"
    
    # 准备编译命令
    local env_vars="GOOS=$goos GOARCH=$goarch"
    if [[ -n "$goarm" ]]; then
        env_vars="$env_vars GOARM=$goarm"
    fi
    if [[ -n "$gomips" ]]; then
        env_vars="$env_vars GOMIPS=$gomips"
    fi
    
    if [[ -n "$SOURCE_FILE" ]]; then
        local build_cmd="$env_vars go build -trimpath -ldflags='-s -w' -o '${output_dir}/${output_name}' $SOURCE_FILE"
    else
        local build_cmd="$env_vars go build -trimpath -ldflags='-s -w' -o '${output_dir}/${output_name}'"
    fi
    
    # 执行编译
    if eval "$build_cmd" 2>/dev/null; then
        local file_size=$(du -h "${output_dir}/${output_name}" | cut -f1)
        echo -e "${GREEN}✓ ${platform} 编译成功 (${file_size})${NC}"
        echo -e "  输出文件: ${output_dir}/${output_name}"
        return 0
    else
        echo -e "${RED}✗ ${platform} 编译失败${NC}"
        return 1
    fi
}

# 编译所有平台
build_all() {
    echo -e "${YELLOW}开始编译所有支持的平台...${NC}"
    echo
    
    local success_count=0
    local fail_count=0
    local failed_platforms=()
    
    for platform in "${PLATFORMS[@]}"; do
        if build_single "$platform"; then
            ((success_count++))
        else
            ((fail_count++))
            failed_platforms+=("$platform")
        fi
        echo
    done
    
    echo -e "${BLUE}================================${NC}"
    echo -e "${GREEN}编译完成统计:${NC}"
    echo -e "${GREEN}成功: ${success_count}${NC}"
    echo -e "${RED}失败: ${fail_count}${NC}"
    
    if [ ${#failed_platforms[@]} -gt 0 ]; then
        echo -e "${RED}失败的平台:${NC}"
        for platform in "${failed_platforms[@]}"; do
            echo -e "  ${RED}- ${platform}${NC}"
        done
    fi
    echo -e "${BLUE}================================${NC}"
}

# 询问是否清理缓存
ask_cleanup() {
    echo
    echo -e "${YELLOW}是否清理 Go 缓存? (y/N):${NC}"
    read -r cleanup_choice
    
    if [[ "$cleanup_choice" == "y" || "$cleanup_choice" == "Y" ]]; then
        echo -e "${BLUE}正在清理缓存...${NC}"
        go clean -cache -testcache -modcache
        echo -e "${GREEN}✓ 缓存清理完成${NC}"
    else
        echo -e "${YELLOW}跳过缓存清理${NC}"
    fi
}

# 检查 Go 环境
check_go() {
    if ! command -v go &> /dev/null; then
        echo -e "${RED}错误: 未找到 Go 编译器${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Go 版本: $(go version)${NC}"
    echo
}

# 检查源文件
check_source_files() {
    if [[ -n "$SOURCE_FILE" ]]; then
        if [ ! -f "$SOURCE_FILE" ]; then
            echo -e "${RED}错误: 未找到指定的源文件 $SOURCE_FILE${NC}"
            exit 1
        fi
    else
        # 检查是否有.go文件
        if ! ls *.go >/dev/null 2>&1; then
            echo -e "${RED}错误: 当前目录下未找到任何.go文件${NC}"
            exit 1
        fi
    fi
}

# 主函数
main() {
    print_title
    check_go
    
    # 获取编译参数
    #get_build_params
    OUTPUT_NAME="ech-tunnel"
    SOURCE_FILE=""
    
    # 检查源文件
    check_source_files
    
    print_platforms
    
    #if get_user_choice; then
        # 编译所有平台
    #    build_all
    #else
        # 编译单个平台
    #    build_single "$SELECTED_PLATFORM"
    #fi

    build_all
    #build_single "android/386"
    #build_single "android/amd64"
    #build_single "android/arm"
    #build_single "android/arm64"
    #build_single "darwin/386"
    #build_single "darwin/amd64"
    #build_single "darwin/arm"
    #build_single "darwin/arm64"
    #build_single "dragonfly/amd64"
    #build_single "freebsd/386"
    #build_single "freebsd/amd64"
    #build_single "freebsd/arm"
    #build_single "freebsd/arm64"
    #build_single "linux/386"
    #build_single "linux/amd64" 
    #build_single "linux/armv5"
    #build_single "linux/armv6"
    #build_single "linux/armv7"
    #build_single "linux/arm64"
    #build_single "linux/mips-hard"
    #build_single "linux/mips-soft"
    #build_single "linux/mips64" 
    #build_single "linux/mipsle-hard"
    #build_single "linux/mipsle-soft"
    #build_single "linux/mips64le" 
    #build_single "linux/ppc64"
    #build_single "linux/ppc64le"
    #build_single "linux/riscv64"
    #build_single "linux/s390x"
    #build_single "netbsd/386"
    #build_single "netbsd/amd64"
    #build_single "netbsd/arm"
    #build_single "netbsd/arm64"
    #build_single "openbsd/386"
    #build_single "openbsd/amd64"
    #build_single "openbsd/arm"
    #build_single "openbsd/arm64"
    #build_single "plan9/386"
    #build_single "plan9/amd64"
    #build_single "solaris/amd64"
    #build_single "windows/386"
    #build_single "windows/amd64"
    #build_single "windows/arm"
    #build_single "windows/arm64"
    
    #ask_cleanup
    
    echo
    echo -e "${GREEN}编译脚本执行完成!${NC}"
}

# 运行主函数
main "$@"
