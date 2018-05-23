package pl.iterators.jwt

import java.time.Instant
import java.time.temporal.ChronoUnit._
import java.util.{Date, UUID}

import com.auth0.jwt.algorithms.Algorithm
import org.scalatest._

import scala.reflect.ClassTag
import scala.util.{Failure, Success}

// scalafix:off
class JwtClaimSpecs extends FlatSpec with Matchers {
  import JwtClaim.PublicClaims._
  val secret    = "CAFEBABE"
  val algorithm = Algorithm.HMAC512(secret)

  object GenericEncodeDecodeBehaviors {

    def assertDecoded[C: Claims](beforeEncoding: JwtClaim[C],
                                 iss: Issuer = Issuer(),
                                 sub: Subject = Subject(),
                                 jti: JwtId = JwtId(),
                                 aud: Audience = Audience()): Assertion = {
      val token = beforeEncoding.toJwt(algorithm)

      val decodedOrError =
        JwtClaim.fromJwt(algorithm, iss = iss, sub = sub, jti = jti, aud = aud)(token)
      decodedOrError match {
        case Success(decoded) => decoded shouldEqual beforeEncoding
        case Failure(ex)      => fail(ex.getMessage, ex)
      }
    }

    def assertFailed[Ex <: Throwable] = new AssertFailedPartiallyApplied[Ex]
    final class AssertFailedPartiallyApplied[Ex <: Throwable] {

      def apply[C: Claims](
                            beforeEncoding: JwtClaim[C],
                            iss: Issuer = Issuer(),
                            sub: Subject = Subject(),
                            jti: JwtId = JwtId(),
                            aud: Audience = Audience(),
                            decodingAlgorithm: Algorithm = algorithm)(implicit classTag: ClassTag[Ex]): Assertion = {
        val token = beforeEncoding.toJwt(algorithm)

        val decodedOrError =
          JwtClaim.fromJwt(decodingAlgorithm, iss = iss, sub = sub, jti = jti, aud = aud)(token)
        decodedOrError match {
          case Success(_) =>
            fail(s"Claim $beforeEncoding was decoded successfully even if it should not")
          case Failure(ex) => ex shouldBe a[Ex]
        }
      }
    }

    def JwtToken[C: Claims](c: C) {
      it can "be encoded and decoded" in {
        val beforeEncoding = JwtClaim(c)
        assertDecoded(beforeEncoding)
      }
    }
  }

  import GenericEncodeDecodeBehaviors._

  case class SimpleClaims(i: Int, l: Long, d: Double, s: String, b: Boolean, date: Date)
  case class ClaimsWithTraversable(ss: List[String], ls: List[Long], is: List[Int])
  case class ClaimsWithOptions(maybeI: Option[Int], maybeS: Option[String])
  case class MappedClaims(uuid: UUID)
  case class MappedTraversable(uuids: Seq[UUID])

  "JwtClaim with Claims (simple values)" should behave like JwtToken(
    SimpleClaims(100, 123L, -0.5, "whatnot", false, Date.from(Instant.now().truncatedTo(SECONDS))))

  "JwtClaim with Claims (traversables))" should behave like JwtToken(
    ClaimsWithTraversable(List("1", "2", "3"), List(0L), List(1, 2, 3)))

  "JwtClaim with Claims (options))" should behave like JwtToken(ClaimsWithOptions(Some(100), None))

  "JwtClaim with Claims (mapped))" should behave like JwtToken(MappedClaims(UUID.randomUUID()))

  "JwtClaim with Claims (mapped traversable))" should behave like JwtToken(
    MappedTraversable(Seq(UUID.randomUUID())))


}
// scalafix:on

