package pl.iterators.jwt

import java.time.temporal.ChronoUnit
import java.time.{Duration, Instant}
import java.util.{Date, UUID}

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTCreator.Builder
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.{DecodedJWT, Verification}
import pl.iterators.jwt.JwtClaim.PublicClaims._

import scala.collection.immutable.Seq
import scala.util.Try

final case class JwtClaim[+C](privateClaims: C,
                              iss: Issuer = Issuer(),
                              sub: Subject = Subject(),
                              exp: ExpiresAt = ExpiresAt(),
                              nbf: NotBefore = NotBefore(),
                              iat: IssuedAt = IssuedAt(),
                              jti: JwtId = JwtId(),
                              aud: Audience = Audience()) {
  def by(issuer: String)        = copy(iss = iss.set(issuer))
  def about(subject: String)    = copy(sub = sub.set(subject))
  def about(subject: UUID)      = copy(sub = sub.set(subject.toString))
  def as(jwtId: String)         = copy(jti = jti.set(jwtId))
  def to(audience: String)      = copy(aud = aud.set(audience))
  def to(audience: Set[String]) = copy(aud = aud.set(audience))
  def to(audience: Seq[String]) = copy(aud = aud.set(audience))

  def expiresIn(seconds: Long)    = copy(exp = exp.set(seconds))
  def expiresIn(ttl: Duration)    = copy(exp = exp.set(ttl))
  def expiresAt(instant: Instant) = copy(exp = exp.set(instant))

  def startsIn(seconds: Long)    = copy(nbf = nbf.set(seconds))
  def startsIn(ttl: Duration)    = copy(nbf = nbf.set(ttl))
  def startsAt(instant: Instant) = copy(nbf = nbf.set(instant))
  def startsNow                  = copy(nbf = nbf.setNow())

  def issuedIn(seconds: Long)    = copy(iat = iat.set(seconds))
  def issuedIn(ttl: Duration)    = copy(iat = iat.set(ttl))
  def issuedAt(instant: Instant) = copy(iat = iat.set(instant))
  def issuedNow                  = copy(iat = iat.setNow())

  def toJwt[C1 >: C](algorithm: Algorithm)(implicit claims: Claims[C1]): String =
    claims.encoder
      .encode(List(iss, sub, exp, nbf, iat, jti, aud)
        .foldLeft(JWT.create())((builder, publicClaim) => publicClaim.toJwt(builder)))(
        claims.privateClaims(privateClaims))
      .sign(algorithm)

}

object JwtClaim {
  import scala.collection.JavaConverters._

  def fromJwt[C](
                  algorithm: Algorithm,
                  iss: Issuer = Issuer(),
                  sub: Subject = Subject(),
                  jti: JwtId = JwtId(),
                  aud: Audience = Audience())(jwt: String)(implicit claims: Claims[C]): Try[JwtClaim[C]] = {
    val publicClaims = List(iss, sub, ExpiresAt(), NotBefore(), IssuedAt(), jti, aud)
    Try {
      publicClaims
        .foldLeft(JWT.require(algorithm))((verification, publicClaim) =>
          publicClaim.require(verification))
        .build()
        .verify(jwt)
    }.map(decoded =>
      publicClaims.foldLeft(JwtClaim(claims.of(claims.decoder.decode(decoded.getClaims))))(
        (jwtClaim, publicClaim) => publicClaim.setClaim(jwtClaim, decoded)))
  }

  sealed abstract class PublicClaim[T] {
    type Self <: PublicClaim[T]
    val value: Option[T]

    def set(value: T): Self
    def get(decodedJWT: DecodedJWT): Self

    final def toJwt(builder: Builder): Builder = value.fold(builder)(v => withSelf(builder, v))
    protected def withSelf(builder: Builder, t: T): Builder

    final def require(verification: Verification) =
      value.fold(verification)(v => requireSelf(verification, v))
    protected def requireSelf(verification: Verification, t: T): Verification

    def setSelf[A](jwtClaim: JwtClaim[A]): JwtClaim[A]
    final def setClaim[A](jwtClaim: JwtClaim[A], decodedJWT: DecodedJWT): JwtClaim[A] = {
      val newSelf = get(decodedJWT)
      if (newSelf.value.isDefined) newSelf.setSelf(jwtClaim) else jwtClaim
    }
  }

  object PublicClaims {
    final case class Issuer(value: Option[String] = None) extends PublicClaim[String] {
      override type Self = Issuer
      override def set(value: String)                              = copy(Some(value))
      override def get(decodedJWT: DecodedJWT)                     = Issuer(Option(decodedJWT.getIssuer))
      override def setSelf[A](jwtClaim: JwtClaim[A])               = jwtClaim.copy(iss = this)
      override protected def withSelf(builder: Builder, t: String) = builder.withIssuer(t)
      override protected def requireSelf(verification: Verification, t: String) =
        verification.withIssuer(t)
    }
    final case class Subject(value: Option[String] = None) extends PublicClaim[String] {
      override type Self = Subject
      override def set(value: String)                              = copy(Some(value))
      override def get(decodedJWT: DecodedJWT)                     = Subject(Option(decodedJWT.getSubject))
      override def setSelf[A](jwtClaim: JwtClaim[A])               = jwtClaim.copy(sub = this)
      override protected def withSelf(builder: Builder, t: String) = builder.withSubject(t)
      override protected def requireSelf(verification: Verification, t: String) =
        verification.withSubject(t)
    }
    final case class JwtId(value: Option[String] = None) extends PublicClaim[String] {
      override type Self = JwtId
      override def set(value: String)                              = copy(Some(value))
      override def get(decodedJWT: DecodedJWT)                     = JwtId(Option(decodedJWT.getId))
      override def setSelf[A](jwtClaim: JwtClaim[A])               = jwtClaim.copy(jti = this)
      override protected def withSelf(builder: Builder, t: String) = builder.withJWTId(t)
      override protected def requireSelf(verification: Verification, t: String) =
        verification.withJWTId(t)
    }

    sealed abstract class NumericDatePublicClaim extends PublicClaim[Instant] {
      private def now                                           = Instant.now()
      protected final def dateValue(instant: Instant)           = Date.from(instant)
      protected final def instantValue(maybeDate: Option[Date]) = maybeDate.map(_.toInstant)
      protected final def truncated(instant: Instant)           = instant.truncatedTo(ChronoUnit.SECONDS)

      final def set(seconds: Long): Self = set(now.plusSeconds(seconds))
      final def set(ttl: Duration): Self = set(ttl.getSeconds)
      final def setNow(): Self           = set(now)

      //there are verified by the library
      override final protected def requireSelf(verification: Verification, t: Instant) =
        verification
    }
    final case class ExpiresAt(value: Option[Instant] = None) extends NumericDatePublicClaim {
      override type Self = ExpiresAt
      override def set(value: Instant) = copy(Some(truncated(value)))
      override def get(decodedJWT: DecodedJWT) =
        ExpiresAt(instantValue(Option(decodedJWT.getExpiresAt)))
      override def setSelf[A](jwtClaim: JwtClaim[A]) = jwtClaim.copy(exp = this)
      override protected def withSelf(builder: Builder, t: Instant) =
        builder.withExpiresAt(dateValue(t))
    }
    final case class NotBefore(value: Option[Instant] = None) extends NumericDatePublicClaim {
      override type Self = NotBefore
      override def set(value: Instant) = copy(Some(truncated(value)))
      override def get(decodedJWT: DecodedJWT) =
        NotBefore(instantValue(Option(decodedJWT.getNotBefore)))
      override def setSelf[A](jwtClaim: JwtClaim[A]) = jwtClaim.copy(nbf = this)
      override protected def withSelf(builder: Builder, t: Instant) =
        builder.withNotBefore(dateValue(t))
    }
    final case class IssuedAt(value: Option[Instant] = None) extends NumericDatePublicClaim {
      override type Self = IssuedAt
      override def set(value: Instant) = copy(Some(truncated(value)))
      override def get(decodedJWT: DecodedJWT) =
        IssuedAt(instantValue(Option(decodedJWT.getIssuedAt)))
      override def setSelf[A](jwtClaim: JwtClaim[A]) = jwtClaim.copy(iat = this)
      override protected def withSelf(builder: Builder, t: Instant) =
        builder.withIssuedAt(dateValue(t))
    }

    final case class Audience(value: Option[Set[String]] = None) extends PublicClaim[Set[String]] {
      override type Self = Audience
      override def set(value: Set[String]) = copy(Some(value))
      def set(value: String): Self         = set(Set(value))
      override def get(decodedJWT: DecodedJWT) =
        Audience(Option(decodedJWT.getAudience).map(_.asScala.toSet))
      def set(value: TraversableOnce[String]): Self  = set(value.toSet)
      override def setSelf[A](jwtClaim: JwtClaim[A]) = jwtClaim.copy(aud = this)

      override protected def withSelf(builder: Builder, t: Set[String]) =
        if (t.isEmpty) builder
        else if (t.size == 1) builder.withAudience(t.head)
        else builder.withAudience(t.toSeq: _*)
      override protected def requireSelf(verification: Verification, t: Set[String]) =
        if (t.isEmpty) verification
        else if (t.size == 1) verification.withAudience(t.head)
        else verification.withAudience(t.toSeq: _*)
    }
  }
}
