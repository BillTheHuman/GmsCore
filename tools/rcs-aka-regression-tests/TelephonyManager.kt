package android.telephony
open class TelephonyManager {
 companion object { const val APPTYPE_USIM=2; const val AUTHTYPE_EAP_AKA=129 }
 open fun getIccAuthentication(appType:Int,authType:Int,data:String):String? = null
}
