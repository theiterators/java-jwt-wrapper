package pl.iterators.jwt

import java.time.temporal.ChronoUnit._
import java.time.{Duration, Instant}
import java.util.{Date, UUID}

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions._
import org.scalatest._
import shapeless.HNil
import shapeless.record._
import shapeless.syntax.singleton._

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

  implicit val byHandClaims = Claims.of[Record.`"name" -> String, "id" -> Int`.T]

  "JwtClaim with Claims (record-syntax))" should behave like JwtToken(
    ("name" ->> "Marcin") :: ("id" ->> 3) :: HNil)

  "JwtClaim with public headers set" should "be encoded and decoded" in assertDecoded(
    JwtClaim(("name" ->> "Marcin") :: ("id" ->> 3) :: HNil)
      .about("Marcin")
      .to("All the people")
      .by("Test")
      .issuedNow
      .expiresIn(Duration.ofMinutes(1))
      .startsNow)

  it should "be verified" in assertDecoded(
    JwtClaim(("name" ->> "Marcin") :: ("id" ->> 3) :: HNil)
      .about("Marcin")
      .to("All the people")
      .by("Test")
      .as("1")
      .issuedNow
      .expiresIn(Duration.ofMinutes(1))
      .startsNow,
    sub = Subject(Some("Marcin")),
    aud = Audience(Some(Set("All the people"))),
    iss = Issuer(Some("Test")),
    jti = JwtId(Some("1"))
  )

  it should "be verified if the audience header contains at least one required value" in assertDecoded(
    JwtClaim(("name" ->> "Marcin") :: ("id" ->> 3) :: HNil)
      .about("Marcin")
      .to(List("All the people", "Universe"))
      .by("Test")
      .as("1")
      .issuedNow
      .expiresIn(Duration.ofMinutes(1))
      .startsNow,
    aud = Audience(Some(Set("Universe")))
  )

  it should "fail to decode if expired" in assertFailed[TokenExpiredException](
    JwtClaim(("name" ->> "Marcin") :: ("id" ->> 3) :: HNil)
      .issuedAt(Instant.now().minus(2, DAYS))
      .expiresAt(Instant.now().minus(2, HOURS)))

  it should "fail to decode if wrong secret is used" in assertFailed[
    SignatureVerificationException](
    JwtClaim(("name" ->> "Marcin Rzeźnicki") :: ("id" ->> 75643) :: HNil)
      .about("Marcin"),
    decodingAlgorithm = Algorithm.HMAC512("DEADBEEF"))

  it should "fail to decode if wrong algorithm is used" in assertFailed[AlgorithmMismatchException](
    JwtClaim(("name" ->> "Marcin") :: ("id" ->> 3) :: HNil)
      .about("Marcin"),
    decodingAlgorithm = Algorithm.HMAC256("CAFEBABE"))

  it should "fail to decode if required claim is not set" in assertFailed[InvalidClaimException](
    JwtClaim(("name" ->> "Marcin") :: ("id" ->> 3) :: HNil)
      .about("Marcin"),
    sub = Subject(Some("Not Marcin")))

  it should "fail to decode if required claim is missing" in assertFailed[InvalidClaimException](
    JwtClaim(("name" ->> "Marcin") :: ("id" ->> 3) :: HNil)
      .about("Marcin"),
    sub = Subject(Some("Marcin")),
    iss = Issuer(Some("Test")))

  it should "fail to decode if audience header does not contain any required value" in assertFailed[
    InvalidClaimException](
    JwtClaim(("name" ->> "Marcin Rzeźnicki") :: ("id" ->> 2434657) :: HNil)
      .to(List("All the people", "All the cats")),
    aud = Audience(Some(Set("All the dogs", "All the hobbitses")))
  )

  sealed trait Hierarchy
  case class Class1(a: Int)    extends Hierarchy
  case class Class2(a: String) extends Hierarchy

  "JwtClaim with Claims (sealed trait hierarchy #1))" should behave like JwtToken[Hierarchy](
    Class1(10))
  "JwtClaim with Claims (sealed trait hierarchy #2))" should behave like JwtToken[Hierarchy](
    Class2("10"))


}
// scalafix:on

