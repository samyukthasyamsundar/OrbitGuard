#pragma once
// A simple circular-orbit model, used to place the simulated satellite on the dashboard map.
//
// This is a visualisation aid, not orbital mechanics: the orbit is a perfect circle, there is no
// perturbation (J2, drag), the Sun direction is fixed, and Earth is a sphere. It is deliberately
// simple so it can be tested exactly. A real ground station would propagate a TLE with SGP4.
//
// It is driven by the same orbital phase the telemetry generator uses to decide eclipse, so what the
// map shows (sunlit or in shadow) agrees with the battery and temperature the satellite reports.
#include <cstdint>
#include <vector>

namespace orbitguard {

struct GeoPosition {
    double lat_deg = 0;   // -90..90
    double lon_deg = 0;   // -180..180
    bool sunlit = true;
};

struct OrbitParams {
    double inclination_deg = 51.6;   // like the ISS; must be in [0, 180]
    double period_s = 90.0 * 60.0;   // must be > 0
    double raan_deg = 0.0;           // longitude of the ascending node at t = 0
    // Earth rotates 360 deg per sidereal day; positive east.
    double earth_rotation_deg_per_s = 360.0 / 86164.0905;
    // Fraction of each orbit spent in Earth's shadow. Matches TelemetryGenerator (phase > 0.63).
    double eclipse_fraction = 0.37;

    bool valid() const;
};

// Position of the sub-satellite point `t_s` seconds after the satellite crossed the ascending node.
// `t_s` may be negative or very large; the result is always a valid latitude and longitude.
GeoPosition position_at(const OrbitParams& p, double t_s);

// Orbital phase in [0, 1) at time t_s (0 = ascending node).
double orbital_phase(const OrbitParams& p, double t_s);

// The ground track from t0 over `duration_s`, sampled every `step_s`, for drawing the path.
// Capped at 2000 points so a bad argument cannot allocate without bound.
std::vector<GeoPosition> ground_track(const OrbitParams& p, double t0_s, double duration_s, double step_s);

}  // namespace orbitguard
