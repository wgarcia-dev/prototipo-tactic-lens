import React, {lazy,Suspense} from 'react'
import {createRoot} from 'react-dom/client'
import {BrowserRouter,Link,NavLink,Route,Routes} from 'react-router-dom'
import {Activity,Database,FileUp,Fingerprint,LayoutDashboard,Shield,ShieldCheck,Workflow} from 'lucide-react'
import './index.css'
import {AuthProvider,useAuth} from './auth/context'
import {AuthBoundary} from './auth/AuthBoundary'
import {SessionControls,SecurityPage} from './auth/SecurityPage'
import {AdminOnly} from './auth/AdminOnly'
import {RealtimeProvider} from './monitoring/Realtime'

const DashboardPage=lazy(()=>import('./pages/DashboardPage').then(module=>({default:module.DashboardPage})))
const SessionsPage=lazy(()=>import('./pages/SessionPages').then(module=>({default:module.SessionsPage})))
const SessionRoute=lazy(()=>import('./pages/SessionPages').then(module=>({default:module.SessionRoute})))
const AnalysisPage=lazy(()=>import('./pages/SessionPages').then(module=>({default:module.AnalysisPage})))
const IncidentListPage=lazy(()=>import('./incidents/EvaluationPage').then(module=>({default:module.IncidentListPage})))
const IncidentDetailPage=lazy(()=>import('./incidents/EvaluationPage').then(module=>({default:module.IncidentDetailPage})))
const IncidentResponsePage=lazy(()=>import('./incidents/response/ResponsePage').then(module=>({default:module.IncidentResponsePage})))
const ResponseBoardPage=lazy(()=>import('./incidents/response/ResponsePage').then(module=>({default:module.ResponseBoardPage})))
const SafeguardsPage=lazy(()=>import('./analysis/SafeguardsPage').then(module=>({default:module.SafeguardsPage})))
const SafeguardProposalsPage=lazy(()=>import('./analysis/SafeguardProposalsPage').then(module=>({default:module.SafeguardProposalsPage})))
const IocsPage=lazy(()=>import('./pages/IocPage').then(module=>({default:module.IocsPage})))
const MitrePage=lazy(()=>import('./pages/MitrePage').then(module=>({default:module.MitrePage})))
const ImportPage=lazy(()=>import('./pages/ImportPage').then(module=>({default:module.ImportPage})))
const AdminUsers=lazy(()=>import('./auth/AdminUsers').then(module=>({default:module.AdminUsers})))

const nav=[['/','Panel principal',LayoutDashboard],['/sesiones','Sesiones y eventos',Database],['/analisis','Análisis LLM',Workflow],['/respuesta-incidentes','Respuesta a incidentes',ShieldCheck],['/incidentes','Incidentes',ShieldCheck],['/iocs','Observables e IoCs',Fingerprint],['/mitre','MITRE ATT&CK',Shield],['/importar','Importar Cowrie',FileUp]] as const
function Shell({children}:{children:React.ReactNode}){const {session}=useAuth();return <div className="min-h-screen md:flex"><aside className="w-full md:w-60 md:sticky md:top-0 md:self-start md:max-h-dvh md:overflow-y-auto bg-[#0f1b2e] border-r line flex flex-col shrink-0"><div className="h-20 flex items-center gap-3 px-6 border-b line"><div className="w-9 h-9 rounded-lg bg-[#164b56] flex items-center justify-center text-[#5ce5de]"><Activity size={21}/></div><div><div className="font-bold tracking-wide text-lg">TacticLens</div><div className="text-[10px] tracking-[.2em] accent">OBSERVATORIO COWRIE</div></div></div><div className="px-5 pt-4 pb-2 text-[10px] tracking-[.13em] muted">NAVEGACIÓN</div><nav className="px-3 space-y-1">{nav.filter(([href])=>href!=='/importar'||session?.usuario.rol==='administrador').map(([href,label,Icon])=><NavLink key={href} to={href} end={href==='/'} className={({isActive})=>`flex items-center gap-3 px-4 py-3 rounded-lg text-sm ${isActive?'bg-[#1b3851] text-white border-l-[3px] border-[#43d7d4]':'text-[#8ea3bb] hover:bg-[#172b42]'}`}><Icon size={16}/>{label}</NavLink>)}</nav><div className="mt-3 px-5 py-4 border-t line text-xs muted"><SessionControls/><span className="inline-block w-2 h-2 rounded-full bg-emerald-400 mr-2"/>Cowrie · entorno controlado<br/><span className="text-[10px]">Prototipo de tesis · UNEMI</span></div></aside><main className="flex-1 min-w-0 bg-[#0b1423]"><div className="max-w-[1500px] mx-auto px-5 md:px-9 py-8">{children}</div></main></div>}
function App(){return <BrowserRouter><AuthProvider><AuthBoundary><RealtimeProvider><Shell><Suspense fallback={<p role="status" className="muted">Cargando módulo…</p>}><Routes><Route path="/" element={<DashboardPage/>}/><Route path="/sesiones" element={<SessionsPage/>}/><Route path="/sesiones/:id" element={<SessionRoute/>}/><Route path="/analisis" element={<AnalysisPage/>}/><Route path="/incidentes" element={<IncidentListPage/>}/><Route path="/incidentes/:id" element={<IncidentDetailPage/>}/><Route path="/respuesta-incidentes" element={<ResponseBoardPage/>}/><Route path="/incidentes/:id/respuesta" element={<IncidentResponsePage/>}/><Route path="/salvaguardas" element={<SafeguardsPage/>}/><Route path="/salvaguardas/propuestas" element={<SafeguardProposalsPage/>}/><Route path="/iocs" element={<IocsPage/>}/><Route path="/mitre" element={<MitrePage/>}/><Route path="/importar" element={<AdminOnly><ImportPage/></AdminOnly>}/><Route path="/seguridad" element={<SecurityPage/>}/><Route path="/usuarios" element={<AdminUsers/>}/><Route path="*" element={<section><p role="alert">La página solicitada no existe.</p><Link className="btn-secondary mt-4 inline-flex" to="/">Volver al panel principal</Link></section>}/></Routes></Suspense></Shell></RealtimeProvider></AuthBoundary></AuthProvider></BrowserRouter>}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App/></React.StrictMode>)
