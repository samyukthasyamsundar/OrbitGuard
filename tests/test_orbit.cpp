#include <gtest/gtest.h>

#include <cmath>
#include <limits>

#include "orbitguard/orbit.hpp"

using namespace orbitguard;

namespace {
OrbitParams iss() { return OrbitParams{}; }  // 51.6 deg, 90 min

double wrap_diff(double a, double b) {  // smallest difference between two longitudes
    double d = std::fmod(std::fabs(a - b), 360.0);
    return d > 180 ? 360 - d : d;
}
}  // namespace

TEST(Orbit, DefaultsAreValid) { EXPECT_TRUE(iss().valid()); }

TEST(Orbit, RejectsBadParameters) {
    const double nan = std::numeric_limits<double>::quiet_NaN();
    for (auto mutate : std::vector<void (*)(OrbitParams&)>{
             [](OrbitParams& p) { p.period_s = 0; },
             [](OrbitParams& p) { p.period_s = -5; },
             [](OrbitParams& p) { p.inclination_deg = 181; },
             [](OrbitParams& p) { p.inclination_deg = -1; },
             [](OrbitParams& p) { p.eclipse_fraction = 1.0; },
             [](OrbitParams& p) { p.eclipse_fraction = -0.1; },
             [](OrbitParams& p) { p.raan_deg = std::numeric_limits<double>::infinity(); }}) {
        OrbitParams p = iss();
        mutate(p);
        EXPECT_FALSE(p.valid());
    }
    OrbitParams p = iss();
    p.period_s = nan;
    EXPECT_FALSE(p.valid());
}

TEST(Orbit, StartsAtTheAscendingNodeOnTheEquator) {
    const GeoPosition g = position_at(iss(), 0);
    EXPECT_NEAR(g.lat_deg, 0.0, 1e-9);
    EXPECT_NEAR(g.lon_deg, 0.0, 1e-9);
}

TEST(Orbit, LatitudeNeverExceedsInclinationAndReachesIt) {
    const OrbitParams p = iss();
    double max_lat = -90, min_lat = 90;
    for (double t = 0; t < p.period_s; t += 5) {
        const double lat = position_at(p, t).lat_deg;
        max_lat = std::max(max_lat, lat);
        min_lat = std::min(min_lat, lat);
        ASSERT_LE(std::fabs(lat), p.inclination_deg + 1e-9) << "t=" << t;
    }
    EXPECT_NEAR(max_lat, p.inclination_deg, 0.05);
    EXPECT_NEAR(min_lat, -p.inclination_deg, 0.05);
}

TEST(Orbit, KeyPhasesAreWhereGeometryRequires) {
    const OrbitParams p = iss();
    EXPECT_NEAR(position_at(p, 0.25 * p.period_s).lat_deg, p.inclination_deg, 1e-9);   // northernmost
    EXPECT_NEAR(position_at(p, 0.50 * p.period_s).lat_deg, 0.0, 1e-9);                 // descending node
    EXPECT_NEAR(position_at(p, 0.75 * p.period_s).lat_deg, -p.inclination_deg, 1e-9);  // southernmost
}

TEST(Orbit, LongitudeAlongATiltedOrbitIsNotUniform) {
    // For an inclined orbit the angle around the Earth's axis advances unevenly: it lags the angle
    // along the orbit near the equator crossings and catches up near the turning points. Worked by
    // hand for a 45 degree orbit at one eighth of the way round, with the Earth held still:
    //   lat = asin(sin 45 * sin 45) = 30.000 deg,   lon = atan2(cos 45 * sin 45, cos 45) = atan(sin 45) = 35.264 deg
    // A formula that ignored the inclination would put the satellite at exactly 45 deg.
    OrbitParams p;
    p.inclination_deg = 45;
    p.earth_rotation_deg_per_s = 0;
    const GeoPosition g = position_at(p, 0.125 * p.period_s);
    EXPECT_NEAR(g.lat_deg, 30.0, 1e-6);
    EXPECT_NEAR(g.lon_deg, 35.2644, 1e-3);
    EXPECT_GT(std::fabs(g.lon_deg - 45.0), 5.0);   // clearly not the naive 45
}

TEST(Orbit, TheSatelliteIsAQuarterAndAHalfTurnFromTheNodeAtThosePhases) {
    OrbitParams p;                                  // any inclination below 90, Earth held still
    p.earth_rotation_deg_per_s = 0;
    EXPECT_NEAR(position_at(p, 0.25 * p.period_s).lon_deg, 90.0, 1e-6);
    // At half an orbit it is on the far side of the Earth: 180 degrees of longitude from the node.
    // (180 and -180 are the same meridian, so compare the angular distance, not the signed value.)
    EXPECT_NEAR(wrap_diff(position_at(p, 0.50 * p.period_s).lon_deg, 0.0), 180.0, 1e-6);
    EXPECT_NEAR(position_at(p, 0.75 * p.period_s).lon_deg, -90.0, 1e-6);
}

TEST(Orbit, GroundTrackShiftsWestByTheEarthsRotationEachOrbit) {
    const OrbitParams p = iss();
    const double shift = p.earth_rotation_deg_per_s * p.period_s;   // about 22.5 degrees
    EXPECT_NEAR(shift, 22.5, 0.1);
    const GeoPosition a = position_at(p, 0);
    const GeoPosition b = position_at(p, p.period_s);
    EXPECT_NEAR(b.lat_deg, a.lat_deg, 1e-9);                         // same latitude after one orbit
    EXPECT_NEAR(wrap_diff(b.lon_deg, a.lon_deg), shift, 1e-6);       // longitude moved by the shift...
    EXPECT_LT(std::fmod(b.lon_deg - a.lon_deg + 540, 360) - 180, 0); // ...to the west
}

TEST(Orbit, WithNoEarthRotationTheTrackRepeatsExactly) {
    OrbitParams p = iss();
    p.earth_rotation_deg_per_s = 0;
    for (double t : {0.0, 100.0, 1234.5, 3000.0}) {
        const GeoPosition a = position_at(p, t), b = position_at(p, t + 3 * p.period_s);
        EXPECT_NEAR(a.lat_deg, b.lat_deg, 1e-9);
        EXPECT_NEAR(wrap_diff(a.lon_deg, b.lon_deg), 0.0, 1e-6);
    }
}

TEST(Orbit, EquatorialOrbitStaysOnTheEquator) {
    OrbitParams p = iss();
    p.inclination_deg = 0;
    for (double t = 0; t < p.period_s; t += 60) EXPECT_NEAR(position_at(p, t).lat_deg, 0.0, 1e-9);
}

TEST(Orbit, PolarOrbitReachesTheEdgeOfTheMapWithoutBlowingUp) {
    OrbitParams p = iss();
    p.inclination_deg = 90;
    EXPECT_NEAR(position_at(p, 0.25 * p.period_s).lat_deg, 90.0, 1e-6);
    for (double t = 0; t < p.period_s; t += 7) {
        const GeoPosition g = position_at(p, t);
        ASSERT_TRUE(std::isfinite(g.lat_deg) && std::isfinite(g.lon_deg)) << t;
    }
}

TEST(Orbit, OutputIsAlwaysAValidCoordinateForAnyTime) {
    const OrbitParams p = iss();
    for (double t : {-1e9, -86400.0, -1.0, 0.0, 1.0, 5400.0, 86400.0, 1e7, 1e12}) {
        const GeoPosition g = position_at(p, t);
        EXPECT_GE(g.lat_deg, -90.0) << t;
        EXPECT_LE(g.lat_deg, 90.0) << t;
        EXPECT_GE(g.lon_deg, -180.0) << t;
        EXPECT_LT(g.lon_deg, 180.0 + 1e-9) << t;
    }
}

TEST(Orbit, NonFiniteTimeOrBadParamsGiveTheDefaultNotGarbage) {
    const GeoPosition g = position_at(iss(), std::numeric_limits<double>::quiet_NaN());
    EXPECT_EQ(g.lat_deg, 0.0);
    OrbitParams bad = iss();
    bad.period_s = 0;
    EXPECT_EQ(position_at(bad, 100).lat_deg, 0.0);
}

TEST(Orbit, PhaseIsPeriodicAndHandlesNegativeTime) {
    const OrbitParams p = iss();
    EXPECT_NEAR(orbital_phase(p, 0), 0.0, 1e-12);
    EXPECT_NEAR(orbital_phase(p, p.period_s / 2), 0.5, 1e-12);
    EXPECT_NEAR(orbital_phase(p, p.period_s * 3 + 100), orbital_phase(p, 100), 1e-9);
    EXPECT_NEAR(orbital_phase(p, -p.period_s / 4), 0.75, 1e-12);
    EXPECT_GE(orbital_phase(p, -1e-9), 0.0);
    EXPECT_LT(orbital_phase(p, -1e-9), 1.0);
}

TEST(Orbit, ShadowFractionMatchesTheConfiguredValue) {
    const OrbitParams p = iss();
    int dark = 0, n = 0;
    for (double t = 0; t < p.period_s; t += 1.0, ++n)
        if (!position_at(p, t).sunlit) ++dark;
    EXPECT_NEAR(static_cast<double>(dark) / n, p.eclipse_fraction, 0.002);
}

TEST(Orbit, ShadowAgreesWithTheTelemetryGeneratorsEclipse) {
    // The generator treats phase > 0.63 as eclipse; the map must agree or it will contradict the
    // battery and temperature the satellite reports.
    const OrbitParams p = iss();
    for (double ph = 0.001; ph < 1.0; ph += 0.001) {
        const bool generator_eclipse = ph > 0.63;
        EXPECT_EQ(position_at(p, ph * p.period_s).sunlit, !generator_eclipse) << "phase " << ph;
    }
}

TEST(GroundTrack, SamplesTheRequestedSpan) {
    const auto t = ground_track(iss(), 0, 600, 60);
    ASSERT_EQ(t.size(), 11u);
    EXPECT_NEAR(t.front().lat_deg, position_at(iss(), 0).lat_deg, 1e-12);
    EXPECT_NEAR(t.back().lon_deg, position_at(iss(), 600).lon_deg, 1e-9);
}

TEST(GroundTrack, IsCappedAndStillCoversTheWholeSpan) {
    const auto t = ground_track(iss(), 0, 1e6, 0.001);   // would be 1e9 points
    EXPECT_EQ(t.size(), 2000u);
    EXPECT_NEAR(t.back().lat_deg, position_at(iss(), 1e6).lat_deg, 1e-6);   // widened step, same end
}

TEST(GroundTrack, BadArgumentsGiveNothing) {
    const double nan = std::numeric_limits<double>::quiet_NaN();
    EXPECT_TRUE(ground_track(iss(), 0, 0, 10).empty());
    EXPECT_TRUE(ground_track(iss(), 0, 100, 0).empty());
    EXPECT_TRUE(ground_track(iss(), 0, -100, 10).empty());
    EXPECT_TRUE(ground_track(iss(), nan, 100, 10).empty());
    EXPECT_TRUE(ground_track(iss(), 0, 100, std::numeric_limits<double>::infinity()).empty());
}
