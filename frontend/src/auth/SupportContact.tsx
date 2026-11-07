import {useEffect,useState} from "react";
import {Link,useLocation} from "react-router-dom";
import {api} from "./client";

type Contact={support_email:string|null;support_enabled:boolean};
let contactRequest:Promise<Contact>|null=null;
export function useSupportContact(){
  const [contact,setContact]=useState<Contact|null>(null),[error,setError]=useState("");
  useEffect(()=>{
    let active=true;
    contactRequest??=api<Contact>("/auth/contacto").catch(error=>{contactRequest=null;throw error;});
    void contactRequest.then(data=>{if(active)setContact(data);}).catch(()=>{if(active)setError("No se pudo cargar el canal oficial de soporte.");});
    return()=>{active=false;};
  },[]);
  return {contact,error};
}

export function SupportContact(){
  const {contact}=useSupportContact();
  const location=useLocation();
  if(location.pathname==="/ayuda") return null;
  return <div className="auth-links mt-5"><Link to="/ayuda">Ayuda y soporte</Link>{contact?.support_email&&<a href={`mailto:${contact.support_email}`}>{contact.support_email}</a>}</div>;
}
