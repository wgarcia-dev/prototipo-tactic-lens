import {useEffect, useId, useRef, useState, type ReactNode, type RefObject} from 'react'
import {Link} from 'react-router-dom'
import {DndContext, DragOverlay, KeyboardSensor, MouseSensor, TouchSensor, useDraggable,
  useDroppable, useSensor, useSensors, pointerWithin, closestCenter, type CollisionDetection,
  type KeyboardCoordinateGetter} from '@dnd-kit/core'
import './safeguards-board.css'

export const states = {pendiente:'Pendientes',en_desarrollo:'En desarrollo',realizada:'Realizadas'} as const
export const risks = {bajo:'Bajo',medio:'Medio',alto:'Alto',critico:'Crítico'} as const
export type Stage = keyof typeof states
export const columns = Object.keys(states) as Stage[]
export type Task = {id_salvaguarda:string;codigo:string;nombre:string;id_sesion:string;estado:Stage;
  nivel_riesgo:keyof typeof risks;prioridad:string|null;responsable:string|null;id_responsable:string|null;
  vence_en:string|null;creado_en:string;asignado_en:string|null;iniciado_en:string|null;finalizado_en:string|null}
export type Wip = {wip_activo:boolean;limite_wip:number;en_desarrollo:number;disponibles:number|null}
export type Page = {items:Task[];total:number}

export function allowedMoves(task:Task, admin:boolean, userId?:string):Stage[] {
  if (task.estado==='realizada') return admin ? ['pendiente','en_desarrollo'] : []
  if (!admin && (!userId || task.id_responsable!==userId)) return []
  return task.estado==='pendiente' ? ['en_desarrollo'] : ['realizada']
}

export function BoardDrawer({title,onClose,children}: {title:string;onClose:()=>void;children:ReactNode}) {
  const ref = useRef<HTMLDialogElement>(null)
  const closeButton = useRef<HTMLButtonElement>(null)
  const id = useId()
  useEffect(()=>{
    const dialog=ref.current
    const previous=document.activeElement
    dialog?.showModal()
    closeButton.current?.focus({preventScroll:true})
    return ()=>{
      dialog?.close()
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus({preventScroll:true})
    }
  },[])
  return <dialog ref={ref} className="safeguard-drawer panel" aria-labelledby={id}
    onCancel={event=>{event.preventDefault();onClose()}}>
    <header className="safeguard-drawer-header"><h2 id={id} className="font-semibold text-lg">{title}</h2>
      <button ref={closeButton} className="btn-secondary shrink-0" onClick={onClose}>Cerrar</button></header>
    <div className="safeguard-drawer-content space-y-4">{children}</div>
  </dialog>
}

const collisions:CollisionDetection = args=> args.pointerCoordinates ? pointerWithin(args) : closestCenter(args)

function Card({task,selected,draggable,onSelect}: {task:Task;selected:boolean;draggable:boolean;onSelect:()=>void}) {
  const {attributes,listeners,setNodeRef,setActivatorNodeRef,isDragging}=useDraggable({id:task.id_salvaguarda,data:{task,stage:task.estado},disabled:!draggable})
  const today = new Intl.DateTimeFormat('en-CA',{timeZone:'America/Guayaquil',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date())
  const overdue = task.estado!=='realizada' && !!task.vence_en && task.vence_en<today
  return <article ref={setNodeRef} className="kanban-card" data-overdue={overdue} data-dragging={isDragging}>
    <div className="kanban-card-head">
      <button className="kanban-card-main text-left" onClick={onSelect} aria-expanded={selected} aria-haspopup="dialog">
        <span className="muted text-xs">{task.codigo}</span><strong className="accent block break-words">{task.nombre}</strong>
        <span className="kanban-card-meta"><span className={`kanban-risk risk-${task.nivel_riesgo}`}>{risks[task.nivel_riesgo]}</span>
          <span>Prioridad {task.prioridad??'sin definir'}</span></span>
        <span className="kanban-card-meta"><span className={task.responsable?'':'text-amber-300'}>{task.responsable??'Sin asignar'}</span>
          {task.vence_en&&<span className={overdue?'text-red-300':''}>{overdue?'Vencida':'Vence'} {task.vence_en}</span>}</span>
      </button>
      {draggable&&<button ref={setActivatorNodeRef} type="button" {...attributes} {...listeners}
        aria-label={`Mover ${task.codigo}`} title="Arrastrar o mover con el teclado" className="kanban-grip">⠿</button>}
    </div>
    <Link className="accent underline text-xs" to={'/sesiones/'+task.id_sesion}>Sesión de origen</Link>
  </article>
}

function Column({stage,page,wip,loading,selected,active,admin,userId,onSelect,onMore}: {
  stage:Stage;page:Page;wip:Wip|null;loading:boolean;selected:string|null;active:Task|null;
  admin:boolean;userId?:string;onSelect:(id:string)=>void;onMore:()=>void}) {
  const {setNodeRef,isOver}=useDroppable({id:stage})
  const available=!!active && allowedMoves(active,admin,userId).includes(stage)
  const capacity=stage==='en_desarrollo' ? wip : null
  const full=capacity?.wip_activo && capacity.disponibles===0
  return <section ref={setNodeRef} className="panel kanban-column" data-target={available} data-over={isOver&&available}>
    <header className="kanban-column-header">
      <div className="flex items-center justify-between gap-2"><h2 className="font-semibold">{states[stage]}</h2>
        <span className="text-sm muted">{capacity ? `${capacity.en_desarrollo}${capacity.wip_activo?`/${capacity.limite_wip}`:''}` : page.total}</span></div>
      {capacity&&<div className="space-y-1" aria-live="polite">
        {capacity.wip_activo&&<progress className="kanban-progress" aria-label="Utilización WIP" max={capacity.limite_wip}
          value={Math.min(capacity.en_desarrollo,capacity.limite_wip)}/>}
        <p className={full?'text-xs text-amber-300':'text-xs muted'}>{!capacity.wip_activo ? 'Sin límite WIP' :
          full ? 'Límite WIP alcanzado · 0 espacios disponibles' : `Espacios disponibles: ${capacity.disponibles}`}</p>
      </div>}
    </header>
    <div className="kanban-scroll" tabIndex={0} role="region" aria-label={`Tarjetas de ${states[stage].toLowerCase()}`}>
      {page.items.map(task=><Card key={task.id_salvaguarda} task={task} selected={selected===task.id_salvaguarda}
        draggable={allowedMoves(task,admin,userId).length>0} onSelect={()=>onSelect(task.id_salvaguarda)}/>)}
      {!loading&&!page.items.length&&<p className="muted text-sm">Sin resultados.</p>}
      {page.items.length<page.total&&<button type="button" className="btn-secondary w-full" disabled={loading} onClick={onMore}>Cargar más</button>}
    </div>
  </section>
}

export function SafeguardBoard({pages,wip,loading,selected,admin,userId,onSelect,onMove,onMore}: {
  pages:Record<Stage,Page>;wip:Wip|null;loading:boolean;selected:string|null;admin:boolean;userId?:string;
  onSelect:(id:string)=>void;onMove:(task:Task,state:Stage)=>void;onMore:(state:Stage)=>void}) {
  return <KanbanInteraction columns={columns} labels={states} allowed={(task:Task)=>allowedMoves(task,admin,userId)}
    onMove={onMove} preview={task=><><strong>{task.codigo}</strong> · {task.nombre}</>}>
    {(active,board)=><div ref={board} className="safeguard-kanban" aria-label="Tablero de salvaguardas">
      {columns.map(stage=><Column key={stage} stage={stage} page={pages[stage]} wip={wip} loading={loading}
        selected={selected} active={active} admin={admin} userId={userId} onSelect={onSelect} onMore={()=>onMore(stage)}/>)}
    </div>}
  </KanbanInteraction>
}

function keyboardColumns<S extends string>(columns:readonly S[]):KeyboardCoordinateGetter {
  return (event,{currentCoordinates,context})=>{
    const direction = {ArrowLeft:-1,ArrowUp:-1,ArrowRight:1,ArrowDown:1}[event.code]
    const index = columns.indexOf((context.over?.id ?? context.active?.data.current?.stage) as S)
    if (!direction || index<0 || !context.collisionRect) return
    event.preventDefault()
    const target=columns[index+direction]
    const rect=target && context.droppableRects.get(target)
    if (!rect) return
    return {x:currentCoordinates.x+rect.left+rect.width/2-context.collisionRect.left-context.collisionRect.width/2,
      y:currentCoordinates.y+Math.min(rect.height/2,85)+rect.top-context.collisionRect.top-context.collisionRect.height/2}
  }
}

export function KanbanInteraction<T,S extends string>({columns,labels,allowed,onMove,preview,children}:{
  columns:readonly S[];labels:Record<S,string>;allowed:(task:T)=>readonly S[];onMove:(task:T,stage:S)=>void;
  preview:(task:T)=>ReactNode;children:(active:T|null,board:RefObject<HTMLDivElement|null>)=>ReactNode;
}) {
  const [active,setActive]=useState<T|null>(null)
  const [pointerDrag,setPointerDrag]=useState(false)
  const board=useRef<HTMLDivElement>(null)
  useEffect(()=>{
    if(!pointerDrag)return
    let point:{clientX:number;clientY:number}|undefined
    const mouse=(event:MouseEvent)=>{point=event}
    const touch=(event:TouchEvent)=>{point=event.touches[0]}
    document.addEventListener('mousemove',mouse)
    document.addEventListener('touchmove',touch,{passive:true})
    const timer=window.setInterval(()=>{
      if(!point)return
      const {clientX,clientY}=point
      for(const scroll of board.current?.querySelectorAll<HTMLElement>('.kanban-scroll')??[]){
        const bounds=scroll.getBoundingClientRect()
        if(clientX<bounds.left||clientX>bounds.right||clientY<bounds.top||clientY>bounds.bottom)continue
        if(clientY<bounds.top+36)scroll.scrollTop-=9
        if(clientY>bounds.bottom-36)scroll.scrollTop+=9
        break
      }
    },24)
    return ()=>{
      document.removeEventListener('mousemove',mouse)
      document.removeEventListener('touchmove',touch)
      window.clearInterval(timer)
    }
  },[pointerDrag])
  const sensors=useSensors(useSensor(MouseSensor,{activationConstraint:{distance:6}}),
    useSensor(TouchSensor,{activationConstraint:{delay:180,tolerance:7}}),
    useSensor(KeyboardSensor,{coordinateGetter:keyboardColumns(columns)}))
  return <DndContext sensors={sensors} collisionDetection={collisions}
    autoScroll={{canScroll:element=>element===document.scrollingElement&&window.matchMedia('(max-width: 900px)').matches}}
    accessibility={{screenReaderInstructions:{draggable:'Pulsa Espacio para tomar una tarjeta. Usa las flechas para elegir la columna. Pulsa Espacio para soltar o Escape para cancelar.'},
      announcements:{onDragStart:()=> 'Tarjeta tomada.',onDragOver:({over})=>over?labels[over.id as S]:'Fuera de las columnas.',
        onDragEnd:({over})=>over?`Tarjeta soltada en ${labels[over.id as S]}.`:'Movimiento cancelado.',onDragCancel:()=> 'Movimiento cancelado.'}}}
    onDragStart={event=>{setActive(event.active.data.current?.task??null);setPointerDrag(!(event.activatorEvent instanceof KeyboardEvent))}}
    onDragCancel={()=>{setActive(null);setPointerDrag(false)}} onDragEnd={event=>{
      setActive(null)
      setPointerDrag(false)
      const task=event.active.data.current?.task as T|undefined
      const stage=event.over?.id as S|undefined
      if(task&&stage&&allowed(task).includes(stage))onMove(task,stage)
    }}>
    {children(active,board)}
    <DragOverlay dropAnimation={null} style={{pointerEvents:'none'}}>{active&&<div className="panel kanban-preview">{preview(active)}</div>}</DragOverlay>
  </DndContext>
}
