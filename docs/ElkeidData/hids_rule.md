# HIDS开源策略列表

<table>
<thead>
  <tr>
    <th>告警ID</th>
    <th>告警名</th>
    <th>描述</th>
    <th>告警类型</th>
    <th>数据类型</th>
    <th>等级</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>hidden_module_detect</td>
    <td>Hidden kernel module</td>
    <td>Hidden Kernel Module Detected</td>
    <td>后门驻留</td>
    <td>Hooks</td>
    <td>critical</td>
  </tr>
  <tr>
    <td>bruteforce_single_source_detect</td>
    <td>Bruteforce from single-source</td>
    <td>Bruteforce from single source address</td>
    <td>暴力破解</td>
    <td>Log Monitor</td>
    <td>medium</td>
  </tr>
  <tr>
    <td>bruteforce_multi_source_detect</td>
    <td>Bruteforce from multi-sources</td>
    <td>Bruteforce from multiple source addresses</td>
    <td>暴力破解</td>
    <td>Log Monitor</td>
    <td>medium</td>
  </tr>
  <tr>
    <td>bruteforce_success_detect</td>
    <td>Bruteforce success</td>
    <td>Bruteforce login attempt ended with succesful password login</td>
    <td>暴力破解</td>
    <td>Log Monitor</td>
    <td>critical</td>
  </tr>
  <tr>
    <td>binary_file_hijack_detect1</td>
    <td>Binary file hijack</td>
    <td>Common binary file hijacking, file creation detection</td>
    <td>变形木马</td>
    <td>execve</td>
    <td>medium</td>
  </tr>
  <tr>
    <td>binary_file_hijack_detect2</td>
    <td>Binary file hijack</td>
    <td>Common binary file Hijacking, file renaming detection</td>
    <td>变形木马</td>
    <td>execve</td>
    <td>critical</td>
  </tr>
  <tr>
    <td>binary_file_hijack_detect3</td>
    <td>Binary file hijack</td>
    <td>Common binary file hijacking, file linkage detection</td>
    <td>变形木马</td>
    <td>execve</td>
    <td>critical</td>
  </tr>
  <tr>
    <td>user_credential_escalation_detect</td>
    <td>User credential escalation</td>
    <td>Non-root user escalate to root privilege</td>
    <td>提权攻击</td>
    <td>Log Monitor</td>
    <td>medium</td>
  </tr>
  <tr>
    <td>privilege_escalation_suid_sgid_detect_1</td>
    <td>User credential escalation</td>
    <td>Non-root user escalete privilege with suid/sgid</td>
    <td>提权攻击</td>
    <td>Log Monitor</td>
    <td>medium</td>
  </tr>
  <tr>
    <td>privilege_escalation_suid_sgid_detect_2</td>
    <td>User credential escalation</td>
    <td>Non-root user escalete privilege with suid/sgid</td>
    <td>提权攻击</td>
    <td>execve</td>
    <td>medium</td>
  </tr>
  <tr>
    <td>reverse_shell_detect_basic</td>
    <td>Reverse shell</td>
    <td>Reverse Shell With Connection</td>
    <td>代码执行</td>
    <td>execve</td>
    <td>critical</td>
  </tr>
  <tr>
    <td>reverse_shell_detect_argv</td>
    <td>Reverse shell</td>
    <td>Reverse-shell-like argv during execution</td>
    <td>代码执行</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>reverse_shell_detect_exec</td>
    <td>Reverse shell</td>
    <td>Reverse shell with exec</td>
    <td>代码执行</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>reverse_shell_detect_pipe</td>
    <td>Reverse shell</td>
    <td>Reverse shell with pipe</td>
    <td>代码执行</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>reverse_shell_detect_perl</td>
    <td>Reverse shell</td>
    <td>Reverse shell with Perl</td>
    <td>代码执行</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>reverse_shell_detect_python</td>
    <td>Reverse shell</td>
    <td>Reverse shell with Python</td>
    <td>代码执行</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>bind_shell_awk_detect</td>
    <td>Bind shell with awk</td>
    <td>Suspecious bind shell with awk</td>
    <td>代码执行</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>pipe_shell_detect</td>
    <td>Double-piped reverse shell</td>
    <td>Double-piped reverse shell</td>
    <td>代码执行</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>suspicious_rce_from_consul_service_detect</td>
    <td>Suspecious RCE like behavior</td>
    <td>Suspecious RCE like behaviors from Consul service</td>
    <td>试探入侵</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>suspicious_rce_from_mysql_service_detect</td>
    <td>Suspecious RCE like behavior</td>
    <td>Suspecious RCE like behaviors from mysql service</td>
    <td>试探入侵</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>dnslog_detect1</td>
    <td>Suspecious query to dnslog</td>
    <td>Suspecious dnslog like query on hosts</td>
    <td>试探入侵</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>dnslog_detect2</td>
    <td>Suspecious query to dnslog</td>
    <td>Suspecious dnslog like query on hosts</td>
    <td>试探入侵</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>container_escape_mount_drive_detect</td>
    <td>Container escape with mounted drive</td>
    <td>Unnecessary behavior inside contianer, mount drive</td>
    <td>提权攻击</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>container_escape_usermode_helper_detect</td>
    <td>Container escape with usermodehelper</td>
    <td>Suspecious contianer escape with usermode helper</td>
    <td>提权攻击</td>
    <td>execve</td>
    <td>high</td>
  </tr>
  <tr>
    <td>signature_scan_maliciou_files_detect</td>
    <td>Malicious files</td>
    <td>Detected abnormal files with maliciou singnature</td>
    <td>静态扫描</td>
    <td>execve</td>
    <td>high</td>
  </tr>
</tbody>
</table>