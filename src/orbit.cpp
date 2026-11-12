#include "orbitguard/orbit.hpp"

#include <algorithm>
#include <cmath>

namespace orbitguard {

namespace {
constexpr double kPi = 3.14159265358979323846;
double rad(double d) { return d * kPi / 180.0; }
double deg(double r) { return r * 180.0 / kPi; }

double wrap_lon(double lon) {
    lon = std::fmod(lon + 180.0, 360.0);
    if (lon < 0) lon += 360.0;
    return lon - 180.0;
}
}  // namespace

bool OrbitParams::valid() const {
    return std::isfinite(inclination_deg) && inclination_deg >= 0 && inclination_deg <= 180 &&
           std::isfinite(period_s) && period_s > 0 && std::isfinite(raan_deg) &&
           std::isfinite(earth_rotation_deg_per_s) && std::isfinite(eclipse_fraction) &&
           eclipse_fraction >= 0 && eclipse_fraction < 1;
}

double orbital_phase(const OrbitParams& p, double t_s) {
    double ph = std::fmod(t_s / p.period_s, 1.0);
    if (ph < 0) ph += 1.0;
    return ph;
}

GeoPosition position_at(const OrbitParams& p, double t_s) {
    GeoPosition out;
    if (!p.valid() || !std::isfinite(t_s)) return out;

    const double phase = orbital_phase(p, t_s);
    const double u = 2.0 * kPi * phase;            // argument of latitude
    const double inc = rad(p.inclination_deg);

    // Position on the celestial sphere for a circular orbit.
    const double sin_lat = std::sin(inc) * std::sin(u);
    out.lat_deg = deg(std::asin(std::clamp(sin_lat, -1.0, 1.0)));

    // Longitude relative to the ascending node, then add the node's own longitude, which drifts
    // westward as the Earth turns underneath the (fixed-in-space) orbit.
    const double lon_in_orbit = std::atan2(std::cos(inc) * std::sin(u), std::cos(u));
    const double node_lon = p.raan_deg - p.earth_rotation_deg_per_s * t_s;
    out.lon_deg = wrap_lon(deg(lon_in_orbit) + node_lon);

    // Shadow: the last `eclipse_fraction` of each orbit (phase > 1 - fraction), as in the generator.
    out.sunlit = phase <= 1.0 - p.eclipse_fraction;
    return out;
}

std::vector<GeoPosition> ground_track(const OrbitParams& p, double t0_s, double duration_s, double step_s) {
    std::vector<GeoPosition> out;
    if (!p.valid() || !std::isfinite(t0_s) || !std::isfinite(duration_s) || !std::isfinite(step_s) ||
        duration_s <= 0 || step_s <= 0)
        return out;
    constexpr std::size_t kMaxPoints = 2000;
    const double n_wanted = duration_s / step_s;
    const std::size_t n = n_wanted >= static_cast<double>(kMaxPoints) ? kMaxPoints
                                                                      : static_cast<std::size_t>(n_wanted) + 1;
    out.reserve(n);
    // If the cap bites, widen the step so the whole requested span is still covered.
    const double eff_step = n_wanted >= static_cast<double>(kMaxPoints) ? duration_s / (kMaxPoints - 1) : step_s;
    for (std::size_t i = 0; i < n; ++i) out.push_back(position_at(p, t0_s + static_cast<double>(i) * eff_step));
    return out;
}

}  // namespace orbitguard
