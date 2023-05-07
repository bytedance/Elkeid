# RASP开源策略列表
<table style="table-layout: fixed; width: 960px">
<colgroup>
<col style="width: 355px">
<col style="width: 80px">
<col style="width: 512px">
</colgroup>
<thead>
  <tr>
    <th>规则名称</th>
    <th>运行时</th>
    <th>规则描述</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>JSP Command Execution</td>
    <td>JVM</td>
    <td>Discover the behavior of command execution from java server pages</td>
  </tr>
  <tr>
    <td>Log4j Exploit</td>
    <td>JVM</td>
    <td>Detected exploit process for log4j</td>
  </tr>
  <tr>
    <td>WebShell Behavior Detect</td>
    <td>JVM</td>
    <td>Suspected WebShell-like behavior found in JVM runtime</td>
  </tr>
  <tr>
    <td>Command Execution Caused By FastJson Deserialization</td>
    <td>JVM</td>
    <td>FastJson deserializes attacker-constructed data, resulting in command execution</td>
  </tr>
  <tr>
    <td>Command Execution In preg_replace Function</td>
    <td>PHP</td>
    <td>Unusual behavior of php preg_replace function for command execution</td>
  </tr>
  <tr>
    <td>BeHinder WebShell Detect</td>
    <td>PHP</td>
    <td>BeHinder WebShell detect by PHP runtime stack trace</td>
  </tr>
</tbody>
</table> 