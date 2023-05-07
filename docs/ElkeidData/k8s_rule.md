# K8S开源策略列表

# k8s 开源策略列表

<table>
<thead>
  <tr>
    <th>策略一级类别</th>
    <th>策略二级类别</th>
    <th>策略三级类别 / 告警名称（风险名称）</th>
    <th>告警描述 </th>
    <th>告警类型</th>
    <th>严重等级</th>
    <th>ATT&amp;CK ID</th>
    <th>风险说明</th>
    <th>处置建议（含关注字段）</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td rowspan="5" bgcolor="#F0FFF0">异常行为</td>
    <td rowspan="3">认证/授权失败</td>
    <td>匿名访问</td>
    <td>匿名用户访问</td>
    <td>试探入侵</td>
    <td>high</td>
    <td>T1133</td>
    <td>检测到匿名用户访问集群，可能有人对集群进行探测攻击。</td>
    <td>1. 通过 UserAgent，操作，请求 URI 等字段判断该操作是否是敏感操作，如果是则可能是有人对集群进行攻击，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查。<br>2. 如果不是，则可以考虑对其进行加白处理（注意：建议结合多个字段进行加白，避免导致漏报）<br><br>关注字段：UserAgent，账户/模拟账户，动作，资源</td>
  </tr>
  <tr>
    <td>认证失败</td>
    <td>枚举/获取 secrets，认证失败</td>
    <td>试探入侵</td>
    <td>low</td>
    <td>T1133</td>
    <td>枚举、获取集群保密字典（Secret）时出现认证失败。攻击者可能会尝试获取集群 secrets 用于后续攻击。</td>
    <td>1. 请先结合客户端的 UserAgent、账户/模拟账户等字段初步判断是否为业务、研发/运维的行为<br>2. 如果是重复出现的预期行为，且经排查后判断安全风险可控，可以考虑对其进行加白（注意：建议结合多个字段进行加白，避免导致漏报）<br>3. 如果是非预期行为，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查<br><br>关注字段：UserAgent， 账户/模拟账户，动作，资源名字</td>
  </tr>
  <tr>
    <td>授权失败</td>
    <td>枚举/获取 secrets，授权失败</td>
    <td>试探入侵</td>
    <td>medium</td>
    <td>T1133</td>
    <td>枚举、获取集群保密字典（Secret）时出现授权失败。攻击者可能会尝试获取 secrets 用于后续攻击。</td>
    <td>1. 请先结合客户端的 UserAgent、账户/模拟账户等字段初步判断是否为业务、研发/运维的行为<br>2. 如果是重复出现的预期行为，且经排查后判断安全风险可控，可以考虑对其进行加白（注意：建议结合多个字段进行加白，避免导致漏报）<br>3. 如果是非预期行为，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查<br><br>关注字段：UserAgent， 账户/模拟账户，动作，资源名字</td>
  </tr>
  <tr>
    <td bgcolor="#FFFFFF">凭据滥用</td>
    <td>凭据滥用</td>
    <td>利用 kubectl 滥用 ServiceAccount</td>
    <td>试探入侵</td>
    <td>critical</td>
    <td>T1078, T1133</td>
    <td>通过 kubectl 客户端工具以 SA 账户身份访问 k8s API Server。攻击者窃取到某个 SA token 后，然后通过 kubectl 工具，附带窃取的 token 向 API Server 发起请求来进行攻击。</td>
    <td>1. 请先通过UserAgent、账户/模拟账户、动作、资源等字段确认是否为预期业务行为<br>2. 如果是重复出现的预期行为，且经排查后判断安全风险可控，可以考虑对其进行加白（注意：建议结合多个字段进行加白，避免导致漏报）<br>3. 如果是非预期行为，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查<br><br>关注字段：UserAgent，账户/模拟账户，动作，资源</td>
  </tr>
  <tr>
    <td>外部代码执行</td>
    <td>外部代码执行</td>
    <td>与 API Server 交互，在 pods 内执行命令</td>
    <td>代码执行</td>
    <td>medium</td>
    <td>T1609</td>
    <td>通过 pods/exec （即 kubectl exec 对应的子资源）在容器内执行任意命令（创建交互式 bash、执行其他命令）。攻击者可能会通过创建 pods/exec 子资源在容器中执行任意命令，从而实现横向移动攻击、凭据窃取等。本策略记录所有的 pods/exec 行为。</td>
    <td>1. 请先通过UserAgent、账户/模拟账户、执行命令等字段确认是否为预期业务行为<br>2. 如果是重复出现的预期行为，且经排查后判断安全风险可控，可以考虑对其进行加白（注意：建议结合多个字段进行加白，避免导致漏报）<br>3. 如果是非预期行为，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查<br><br>关注字段：UserAgent，账户/模拟账户，执行命令</td>
  </tr>
  <tr>
    <td rowspan="3" bgcolor="#FFF5EE">威胁资源</td>
    <td rowspan="2" bgcolor="#FFFFFF">Workloads 部署</td>
    <td>特权容器</td>
    <td>创建具有特权容器的工作负载</td>
    <td>提权攻击</td>
    <td>critical</td>
    <td>T1611, T1610</td>
    <td>监测到有特权容器创建。攻击者可能会通过创建特权容器来横向移动并获取宿主机的控制权。业务在部署服务时，也可能会创建特权容器，如果容器被攻击，则可以轻易实现逃逸，因此非必要不创建。</td>
    <td>1. 请先通过容器所属的业务等字段确认是否为预期业务行为<br>2. 如果是重复出现的预期行为，且经排查后判断安全风险可控，可以考虑对其进行加白（注意：建议结合多个字段进行加白，避免导致漏报）<br>3. 如果是非预期行为，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查<br><br>关注字段：容器所属的业务，UserAgent， 账户/模拟账户</td>
  </tr>
  <tr>
    <td>挂载宿主机敏感文件</td>
    <td>创建挂载宿主机敏感文件的工作负载</td>
    <td>提权攻击</td>
    <td>critical</td>
    <td>T1611, T1610</td>
    <td>创建的容器挂载了宿主机上的敏感目录或文件，比如根目录目录，/proc目录等。<br><br>攻击者可能会创建挂载宿主机敏感目录、文件的容器来提升权限，获取宿主机的控制权并躲避检测。当合法的业务创建挂载宿主机敏感目录、文件的容器时，也会给容器环境带来安全隐患。<br><br>针对前者需要进一步排查异常，针对后者需联系业务进行持续的安全合规整改。</td>
    <td>1. 请先通过容器所属的业务等字段确认是否为预期业务行为<br>2. 如果是重复出现的预期行为，且经排查后判断安全风险可控，可以考虑对其进行加白（注意：建议结合多个字段进行加白，避免导致漏报）<br>3. 如果是非预期行为，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查<br><br>关注字段：容器所属的业务，UserAgent，账户/模拟账户，镜像</td>
  </tr>
  <tr>
    <td bgcolor="#FFFFFF">RoleBinding、ClusterRoleBinding 创建</td>
    <td>创建不安全的 ClusterRole</td>
    <td>创建绑定大权限 ClusterRole 的 ClusterRoleBinding</td>
    <td>后门驻留</td>
    <td>high</td>
    <td>T1078</td>
    <td>创建的 ClusterRoleBinding 绑定了敏感的 ClusterRole，即将某个用户、用户组或服务账户赋予敏感的 ClusterRole 的权限。攻击者可能会为持久化、隐蔽性而创建绑定大权限 ClusterRole 的 ClusterRoleBinding。集群管理员或运维人员也可能会因安全意识不足而创建绑定大权限 ClusterRole 的 ClusterRoleBinding。根据权限最小化原则和 k8s 安全攻防实践，此类 ClusterRoleBinding 会给集群引入较大的安全风险，因此应该极力避免。</td>
    <td>1. 请先结合客户端的 UserAgent、账户/模拟账户等字段初步判断是否为业务、研发/运维的行为<br>2. 如果是运维人员在进行角色绑定，则可以将告警设置为已处理。<br>3. 如果是重复出现的预期行为，且经排查后判断安全风险可控，可以考虑对其进行加白（注意：建议结合多个字段进行加白，避免导致漏报）<br>4. 如果是非预期行为，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查<br><br>关注字段：UserAgent， 账户/模拟账户，主体名字，角色名字</td>
  </tr>
  <tr>
    <td bgcolor="#F0FFF0">漏洞利用行为</td>
    <td bgcolor="#FFFFFF">N/A</td>
    <td>疑似 CVE-2020-8554</td>
    <td>疑似存在通过创建、更新 Service 的 externalIPs 来利用 CVE-2020-8554 的利用行为</td>
    <td>信息搜集</td>
    <td>high</td>
    <td>T1557</td>
    <td>检测到 CVE-2020-8554 的利用特征——创建、更新 Service 并设置 externalIPs。此漏洞的利用途径之一为 创建、更新 Service 时设置了恶意 spec.externalIPs 从而实现中间人攻击。根据实践，Service 的 ExternalIP 属性很少被使用。因此当发生这种行为时，需要运营人员进一步核实 ExternalIP 是否为合法的 IP 地址。</td>
    <td>1. 请先通过UserAgent、账户/模拟账户等字段以及原始日志中的 requestObject.spec.externalIPs 的值确认是否为预期业务行为<br>2. 如果是重复出现的预期行为，且经排查后判断安全风险可控，可以考虑对其进行加白（注意：建议结合多个字段进行加白，避免导致漏报）<br>3. 如果是非预期行为，请通过源 IP 字段以及该 IP 关联的资产信息等来定位发起者身份，进一步排查<br><br>关注字段：UserAgent， 账户/模拟账户,&nbsp;&nbsp;requestObject.spec.externalIPs</td>
  </tr>
</tbody>
</table>