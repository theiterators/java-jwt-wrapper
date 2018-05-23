package pl.iterators.jwt

import java.util.{Date, UUID, Map => jMap}

import com.auth0.jwt.JWTCreator.Builder
import com.auth0.jwt.exceptions.InvalidClaimException
import com.auth0.jwt.interfaces.Claim

import scala.collection.generic.CanBuildFrom
import scala.language.higherKinds
import scala.reflect.ClassTag

abstract class PrivateClaimType[T] {
  def encode(builder: Builder)(name: String, t: T): Builder
  final def decode(claims: jMap[String, Claim])(name: String): T = {
    val claim = claims.get(name)
    if ((claim eq null) || claim.isNull) decodeNullClaim(name) else decodeClaim(claim)
  }
  def decodeClaim(claim: Claim): T

  def decodeNullClaim(name: String): T =
    throw new InvalidClaimException(s"The Claim '$name' is missing")
}

trait DefaultPrivateClaimTypes {
  implicit object BooleanType extends PrivateClaimType[Boolean] {
    override def encode(builder: Builder)(name: String, t: Boolean) = builder.withClaim(name, t)
    override def decodeClaim(claim: Claim)                          = claim.asBoolean()
  }
  implicit object IntType extends PrivateClaimType[Int] {
    override def encode(builder: Builder)(name: String, t: Int) =
      builder.withClaim(name, Int.box(t))
    override def decodeClaim(claim: Claim) = claim.asInt()
  }
  implicit object LongType extends PrivateClaimType[Long] {
    override def encode(builder: Builder)(name: String, t: Long) =
      builder.withClaim(name, Long.box(t))
    override def decodeClaim(claim: Claim) = claim.asLong()
  }
  implicit object DoubleType extends PrivateClaimType[Double] {
    override def encode(builder: Builder)(name: String, t: Double) =
      builder.withClaim(name, Double.box(t))
    override def decodeClaim(claim: Claim) = claim.asDouble()
  }
  implicit object StringType extends PrivateClaimType[String] {
    override def encode(builder: Builder)(name: String, t: String) = builder.withClaim(name, t)
    override def decodeClaim(claim: Claim)                         = claim.asString()
  }
  implicit object DateType extends PrivateClaimType[Date] {
    override def encode(builder: Builder)(name: String, t: Date) = builder.withClaim(name, t)
    override def decodeClaim(claim: Claim)                       = claim.asDate()
  }
  implicit object StringArrayType extends PrivateClaimType[Array[String]] {
    override def encode(builder: Builder)(name: String, t: Array[String]) =
      builder.withArrayClaim(name, t)
    override def decodeClaim(claim: Claim) = claim.asArray(classOf[String])
  }
  implicit object IntArrayType extends PrivateClaimType[Array[Int]] {
    override def encode(builder: Builder)(name: String, t: Array[Int]) =
      builder.withArrayClaim(name, t.map(Int.box))
    override def decodeClaim(claim: Claim) =
      claim.asArray(classOf[java.lang.Integer]).map(Int.unbox(_))
  }
  implicit object LongArrayType extends PrivateClaimType[Array[Long]] {
    override def encode(builder: Builder)(name: String, t: Array[Long]) =
      builder.withArrayClaim(name, t.map(Long.box))
    override def decodeClaim(claim: Claim) =
      claim.asArray(classOf[java.lang.Long]).map(Long.unbox(_))
  }

  implicit def OptionType[T](implicit base: PrivateClaimType[T]): PrivateClaimType[Option[T]] =
    new PrivateClaimType[Option[T]] {
      override def encode(builder: Builder)(name: String, maybeT: Option[T]) =
        maybeT.fold(builder)(t => base.encode(builder)(name, t))
      override def decodeClaim(claim: Claim)     = Some(base.decodeClaim(claim))
      override def decodeNullClaim(name: String) = None
    }

  implicit def TraversableType[T, TT[_] <: TraversableOnce[_ <: T]](
                                                                     implicit classTag: ClassTag[T],
                                                                     canBuildFrom: CanBuildFrom[Nothing, T, TT[T]],
                                                                     baseArray: PrivateClaimType[Array[T]]): PrivateClaimType[TT[T]] =
    new PrivateClaimType[TT[T]] {
      override def encode(builder: Builder)(name: String, ts: TT[T]) =
        baseArray.encode(builder)(name, ts.toArray[T])
      override def decodeClaim(claim: Claim) = baseArray.decodeClaim(claim).to[TT]
    }
}

object PrivateClaimType extends DefaultPrivateClaimTypes {

  final class Mapped[T, U](val map: T => U, val comap: U => T, base: PrivateClaimType[U])
    extends PrivateClaimType[T] {
    override def encode(builder: Builder)(name: String, t: T) = base.encode(builder)(name, map(t))
    override def decodeClaim(claim: Claim)                    = comap(base.decodeClaim(claim))
    override def decodeNullClaim(name: String)                = comap(base.decodeNullClaim(name))
  }

  object Mapped {

    def apply[T, U](tu: T => U, ut: U => T)(implicit base: PrivateClaimType[U]): Mapped[T, U] =
      new Mapped(tu, ut, base)
  }

  implicit def UuidType: Mapped[UUID, String] = Mapped(_.toString, UUID.fromString(_))
  implicit def MappedArrayType[T, U](implicit mapped: Mapped[T, U],
                                     baseArray: PrivateClaimType[Array[U]],
                                     clsT: ClassTag[T],
                                     clsU: ClassTag[U]): Mapped[Array[T], Array[U]] =
    Mapped(_.map(mapped.map).toArray, _.map(mapped.comap).toArray)

}
