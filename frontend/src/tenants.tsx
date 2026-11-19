import { Box,Button,Card,CardContent,Chip,Divider,Stack,Typography } from "@mui/material";
import { Link as RouterLink,useLocation,useNavigate } from "react-router-dom";
import type {ViewEnvelope} from "./contracts";
import type { Actions } from "./shared";
import { Heading,Panel } from "./shared";
import { t,useLocale } from "./i18n";

type TenantPage = ViewEnvelope<"TenantAdminView"|"TenantListView"|"TenantDetailView"|"TenantInvitationView"|"TenantChoiceView">;
export function Tenants({page,mutate,ask,editor}: {page:TenantPage}&Actions){
  useLocale();
  const {view,data}=page;
  const navigate=useNavigate();
  const {pathname}=useLocation();
  if(view==="TenantAdminView"){
    return <><Heading title={t("租户管理")} description={t("管理组织租户的基本状态；业务权限和资源由应用自行管理。")}/><Panel title={t("组织租户")}><Stack spacing={2}>{data.tenants.map(row=><Stack key={row.id} direction="row" sx={{alignItems:"center",justifyContent:"space-between"}}><Box><Typography sx={{fontWeight:600}}>{row.name} ({row.slug||"—"})</Typography><Typography variant="body2" color="text.secondary">{row.members} {t("名成员")} · {row.status}</Typography></Box><Button color={row.status==="active"?"error":"primary"} variant="outlined" onClick={()=>ask(t(row.status==="active"?"停用组织":"恢复组织"),`/dashboard/tenants/${row.id}/toggle`)}>{t(row.status==="active"?"停用":"恢复")}</Button></Stack>)}</Stack></Panel></>;
  }
  if(view==="TenantChoiceView"){
    return <Box sx={{maxWidth:520,mx:"auto",mt:10,p:2}}>
      <Card><CardContent>
        <Heading title={t("选择工作空间")} description={t("本次授权将限定在选择的个人或组织空间内。")}/>
        <Stack spacing={1.5}>{data.choices.length===0?<Typography color="text.secondary">{t("当前没有可访问的工作空间。")}</Typography>:data.choices.map(option=>
          <Button fullWidth key={option.id} variant="outlined" onClick={()=>mutate("/oauth2/authorize/tenant",{tenant_id:option.id,token:data.token})}>
            {option.name} · {option.kind==="personal"?t("个人"):t("组织")}
          </Button>)}</Stack>
      </CardContent></Card>
    </Box>;
  }
  if(view==="TenantListView"){
    return <>
      <Heading title={t("我的空间与组织")} description={t("个人身份统一，个人和组织数据分别存放。")}
        action={<Button variant="contained" onClick={()=>editor(t("创建组织"),"/account/tenants",[
          {name:"name",label:t("组织名称"),required:true},
          {name:"slug",label:t("组织标识"),required:true}
        ])}>{t("创建组织")}</Button>}/>
      <Panel title={t("已加入的工作空间")}><Stack spacing={1}>
        {data.tenants.map(space=><Button key={space.id} component={RouterLink} to={`/account/tenants/${space.id}`} variant="outlined" sx={{justifyContent:"space-between",textAlign:"left"}}>
          {space.name} ({space.kind==="personal"?t("个人"):t("组织")}) · {space.role}
        </Button>)}
      </Stack></Panel>
    </>;
  }
  if(view==="TenantInvitationView"){
    return <>
      <Heading title={t("加入组织")} description={data.invitation.tenant_name}/>
      <Panel title={t("邀请详情")}>
        <Typography sx={{mb:2}}>{data.invitation.email} · {data.invitation.role}</Typography>
        {!data.verified_email||data.user_email?.toLowerCase()!==data.invitation.email.toLowerCase()?
          <Typography color="error">{t("请使用与邀请邮箱一致且已验证的账号接受邀请。")}</Typography>:
          <Button variant="contained" onClick={()=>mutate(pathname,{},()=>navigate("/account/tenants"))}>{t("接受邀请")}</Button>}
      </Panel>
    </>;
  }
  const {tenant,members,invitations,current_user_id}=data;
  const admin=tenant.role==="owner"||tenant.role==="admin";
  return <>
    <Heading title={tenant.name} back="/account/tenants" description={tenant.kind==="personal"?t("个人工作空间"):t("组织工作空间")}/>
    <Panel title={t("组织资料")}>
      <Stack direction="row" spacing={2} sx={{alignItems:"center",mb:2}}>
        <Chip label={tenant.role}/><Chip variant="outlined" label={tenant.status}/>
        {tenant.slug&&<Typography color="text.secondary">/{tenant.slug}</Typography>}
      </Stack>
      {admin&&tenant.kind==="organization"&&<Button variant="outlined" onClick={()=>editor(t("修改组织名称"),`/account/tenants/${tenant.id}/edit`,[{name:"name",label:t("组织名称"),required:true}],{name:tenant.name})}>{t("编辑组织")}</Button>}
      {tenant.kind==="organization"&&<Button color="error" sx={{ml:2}} onClick={()=>ask(t("退出组织"),`/account/tenants/${tenant.id}/leave`,{},t("退出后将不能再以此组织身份访问应用。"))}>{t("退出组织")}</Button>}
    </Panel>
    {tenant.kind==="organization"&&<Panel title={t("组织成员")} action={admin?<Button variant="contained" onClick={()=>editor(t("邀请成员"),`/account/tenants/${tenant.id}/invitations`,[
      {name:"email",label:t("成员邮箱"),type:"email",required:true},
      {name:"role",label:t("治理角色"),required:true,options:[["member",t("成员")],["admin",t("管理员")]]}
    ],{role:"member"})}>{t("邀请成员")}</Button>:undefined}>
      <Stack spacing={1.5}>{members.map(member=><Box key={member.user_id}><Stack direction={{xs:"column",sm:"row"}} sx={{alignItems:{sm:"center"},justifyContent:"space-between"}} spacing={1}>
        <Box><Typography sx={{fontWeight:600}}>{member.name} ({member.username})</Typography><Typography variant="caption" color="text.secondary">{member.role}</Typography></Box>
        {admin&&<Stack direction="row" spacing={1}>
          {tenant.role==="owner"&&member.role!=="owner"&&<Button size="small" onClick={()=>ask(t("设为所有者"),`/account/tenants/${tenant.id}/members/${member.user_id}`,{action:"owner"})}>{t("设为所有者")}</Button>}
          {member.role!=="member"&&(tenant.role==="owner"||member.role!=="owner")&&<Button size="small" onClick={()=>ask(t("设为成员"),`/account/tenants/${tenant.id}/members/${member.user_id}`,{action:"member"})}>{t("设为成员")}</Button>}
          {member.role==="member"&&<Button size="small" onClick={()=>ask(t("设为管理员"),`/account/tenants/${tenant.id}/members/${member.user_id}`,{action:"admin"})}>{t("设为管理员")}</Button>}
          {member.user_id!==current_user_id&&<Button color="error" size="small" onClick={()=>ask(t("移除成员"),`/account/tenants/${tenant.id}/members/${member.user_id}`,{action:"remove"})}>{t("移除")}</Button>}
        </Stack>}
      </Stack><Divider sx={{mt:1}}/></Box>)}</Stack>
    </Panel>}
    {admin&&tenant.kind==="organization"&&<Panel title={t("邀请记录")}><Stack spacing={1}>{invitations.map(inv=><Stack key={inv.id} direction="row" sx={{alignItems:"center",justifyContent:"space-between"}}>
      <Typography>{inv.email} · {inv.role} · {inv.status}</Typography>
      {inv.status==="pending"&&<Button size="small" color="error" onClick={()=>ask(t("撤销邀请"),`/account/tenants/${tenant.id}/invitations/${inv.id}`)}>{t("撤销")}</Button>}
    </Stack>)}</Stack></Panel>}
  </>;
}
