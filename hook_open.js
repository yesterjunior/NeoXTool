// Frida脚本: test_attach_v12.js

console.log("[*] 测试脚本(v12)已注入...");

// 延迟1秒执行，确保App已完成初步初始化
setTimeout(function() {

    // Java.perform 确保我们处于正确的Java线程上下文中
    Java.perform(function() {
        console.log("\n[+] 脚本成功在目标进程中运行！");
        console.log("[+] Java 环境准备就绪。");
        console.log("[+] 如果您能看到这条消息，说明附加成功且程序未崩溃。");
    });

}, 1000); // 延迟1000毫秒