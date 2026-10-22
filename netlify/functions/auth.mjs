import crypto from 'node:crypto';
// Server-side defaults configured for this project. Keep this repository private.
const ADMIN_PASSWORD = '0632527308gui';
const ADMIN_SECRET = 'lG1J1JAgQ-NvqiP4e2IqLeFSeGkl7OZsNn1Qnh_KEoREZDdLNRhWT9QaOfqAb4NW';
const secret=()=>process.env.ADMIN_SECRET || ADMIN_SECRET;
function sign(value){return crypto.createHmac('sha256',secret()).update(value).digest('base64url')}
function makeToken(){const payload=Buffer.from(JSON.stringify({role:'admin',exp:Date.now()+8*60*60*1000})).toString('base64url');return `${payload}.${sign(payload)}`}
function valid(token){if(!secret()||!token)return false;const [payload,sig]=token.split('.');if(!payload||!sig)return false;const expected=sign(payload);const a=Buffer.from(sig),b=Buffer.from(expected);if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return false;try{const p=JSON.parse(Buffer.from(payload,'base64url').toString());return p.role==='admin'&&p.exp>Date.now()}catch{return false}}
const json=(statusCode,body)=>({statusCode,headers:{'Content-Type':'application/json','Cache-Control':'no-store'},body:JSON.stringify(body)});
export default async (event)=>{if(event.httpMethod==='OPTIONS')return {statusCode:204,headers:{'Access-Control-Allow-Origin':'*'}};if(event.httpMethod==='GET'){const token=(event.headers.authorization||event.headers.Authorization||'').replace(/^Bearer\s+/i,'');return valid(token)?json(200,{ok:true}):json(401,{error:'เซสชันแอดมินหมดอายุ กรุณาเข้าสู่ระบบใหม่'})}if(event.httpMethod!=='POST')return json(405,{error:'Method not allowed'});let body={};try{body=JSON.parse(event.body||'{}')}catch{return json(400,{error:'ข้อมูลไม่ถูกต้อง'})}if(typeof body.password!=='string'||body.password!==(process.env.ADMIN_PASSWORD || ADMIN_PASSWORD))return json(401,{error:'รหัสแอดมินไม่ถูกต้อง'});return json(200,{token:makeToken()})};
export { valid };
