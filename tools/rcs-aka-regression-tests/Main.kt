package tests

import android.telephony.TelephonyManager
import org.microg.gms.constellation.core.verification.ts43.EapAkaService
import org.microg.gms.constellation.core.verification.ts43.Fips186Prf
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private val ck = ByteArray(16) { (it + 1).toByte() }
private val ik = ByteArray(16) { (it + 17).toByte() }
private val res = ByteArray(8) { (it + 33).toByte() }
private const val imsi = "001010123456789"
private const val operator = "00101"
private val kAut = Fips186Prf.deriveKeys("0$imsi@nai.epc.mnc001.mcc001.3gppnetwork.org".toByteArray(),ik,ck).getValue("K_aut")
private fun mac(bytes:ByteArray,key:ByteArray=kAut) = Mac.getInstance("HmacSHA1").apply { init(SecretKeySpec(key,"HmacSHA1")) }.doFinal(bytes).copyOf(16)
private fun encode(b:ByteArray)=java.util.Base64.getEncoder().encodeToString(b)
private fun attr(type:Int)=byteArrayOf(type.toByte(),5,0,0)+ByteArray(16) { (it+type).toByte() }
private fun challenge(types:List<Int> = listOf(1,2,11),signingKey:ByteArray=kAut):ByteArray {
 val attributes=types.fold(ByteArray(0)) { a,t -> a + if(t in listOf(1,2,11)) attr(t) else byteArrayOf(t.toByte(),1,0,0) }
 val packet=ByteBuffer.allocate(8+attributes.size).apply {put(1);put(7);putShort((8+attributes.size).toShort());put(23);put(1);putShort(0);put(attributes)}.array()
 var pos=8;val offsets=mutableListOf<Int>()
 while(pos<packet.size){if(packet[pos].toInt()==11){offsets.add(pos+4);packet.fill(0,pos+4,pos+20)};pos+=(packet[pos+1].toInt() and 255)*4}
 if(offsets.size==1)mac(packet,signingKey).copyInto(packet,offsets[0])
 return packet
}
private class Sim(var bytes:ByteArray=byteArrayOf(0xdb.toByte(),8)+res+byteArrayOf(16)+ck+byteArrayOf(16)+ik):TelephonyManager(){
 var calls=0
 override fun getIccAuthentication(appType:Int,authType:Int,data:String):String {calls++;check(appType==2&&authType==129);return encode(bytes)}
}
private fun respond(packet:ByteArray,sim:Sim=Sim())=EapAkaService(sim).performSimAkaAuth(encode(packet),imsi,operator)
fun main(){
 var passed=0;var failed=0
 fun test(name:String,f:()->Unit){try{f();println("PASS $name");passed++}catch(t:Throwable){println("FAIL $name: ${t.javaClass.simpleName}: ${t.message}");failed++}}
 test("valid challenge responds with matching ID, RES and response MAC"){
  val out=java.util.Base64.getDecoder().decode(respond(challenge()) ?: error("no response"))
  check(out[0].toInt()==2&&out[1].toInt()==7&&out[5].toInt()==1)
  check(out.copyOfRange(12,20).contentEquals(res));val actual=out.takeLast(16).toByteArray();out.fill(0,out.size-16,out.size);check(actual.contentEquals(mac(out)))
 }
 test("invalid challenge MAC is rejected"){val p=challenge();p[p.lastIndex]=(p.last().toInt() xor 1).toByte();check(respond(p)==null)}
 test("missing MAC is rejected before SIM use"){val s=Sim();check(respond(challenge(listOf(1,2)),s)==null);check(s.calls==0)}
 test("MAC may precede RAND and AUTN"){check(respond(challenge(listOf(11,2,1)))!=null)}
 test("duplicate RAND is rejected before SIM use"){val s=Sim();check(respond(challenge(listOf(1,2,1,11)),s)==null);check(s.calls==0)}
 test("duplicate MAC is rejected"){check(respond(challenge(listOf(1,2,11,11)))==null)}
 test("overstated EAP length is rejected"){val p=challenge();p[3]=(p.size+4).toByte();check(respond(p)==null)}
 test("zero-length trailing attribute is rejected"){val p=challenge()+byteArrayOf(128.toByte(),0,0,0);p[3]=p.size.toByte();check(respond(p)==null)}
 test("unknown non-skippable attribute is rejected"){val s=Sim();check(respond(challenge(listOf(1,2,7,11)),s)==null);check(s.calls==0)}
 test("unknown skippable attribute participates in MAC"){check(respond(challenge(listOf(1,128,2,11)))!=null)}
 test("modified EAP identifier breaks the MAC"){val p=challenge();p[1]=8;check(respond(p)==null)}
 test("link padding beyond EAP length is ignored"){check(respond(challenge()+byteArrayOf(99,99))!=null)}
 test("invalid relay Base64 returns null"){check(EapAkaService(Sim()).performSimAkaAuth("%not-base64%",imsi,operator)==null)}
 test("malformed SIM key length is rejected"){val s=Sim(byteArrayOf(0xdb.toByte(),8)+res+byteArrayOf(15)+ck.copyOf(15)+byteArrayOf(16)+ik);check(respond(challenge(),s)==null)}
 test("valid synchronization failure still returns AUTS"){
  val auts=ByteArray(14){it.toByte()};val out=java.util.Base64.getDecoder().decode(respond(challenge(),Sim(byteArrayOf(0xdc.toByte(),14)+auts))?:error("no AUTS"));check(out[5].toInt()==4);check(out.copyOfRange(10,24).contentEquals(auts))
 }
 test("custom carrier realm is preserved in key derivation"){
  val identity="0$imsi@wlan.mnc001.mcc001.3gppnetwork.org"
  val key=Fips186Prf.deriveKeys(identity.toByteArray(),ik,ck).getValue("K_aut")
  val service=EapAkaService(Sim());val request=encode(challenge(signingKey=key))
  val method=EapAkaService::class.java.methods.firstOrNull { it.name=="performSimAkaAuth"&&it.parameterCount==4 }
  val reply=if(method!=null)method.invoke(service,request,imsi,operator,identity) as String? else service.performSimAkaAuth(request,imsi,operator)
  val out=java.util.Base64.getDecoder().decode(reply ?: error("custom-realm response missing"))
  val actual=out.takeLast(16).toByteArray();out.fill(0,out.size-16,out.size)
  check(actual.contentEquals(mac(out,key))){"response MAC used a different identity from the initial EAP_ID"}
 }
 println("RESULT passed=$passed failed=$failed");check(failed==0){"$failed regression failures"}
}
