package android.util
object Base64 {
 const val DEFAULT=0; const val NO_WRAP=2
 fun decode(s:String,flags:Int):ByteArray = java.util.Base64.getDecoder().decode(s.filterNot { it.isWhitespace() })
 fun encodeToString(b:ByteArray,flags:Int):String = java.util.Base64.getEncoder().encodeToString(b)
}
