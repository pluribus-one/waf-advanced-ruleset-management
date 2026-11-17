use http::Version;


/// Convert nginx HTTP version value into `http::Version`.
///
/// nginx stores the HTTP version internally as a numeric value.
///
/// The conversion is performed here so that the rest of the
/// converter works only with Rust HTTP types.
pub fn convert_version(
    version: usize,
) -> Version {

    match version {

        //
        // HTTP/1.0
        //
        1000 => Version::HTTP_10,


        //
        // HTTP/1.1
        //
        1001 => Version::HTTP_11,


        //
        // HTTP/2
        //
        2000 => Version::HTTP_2,


        //
        // HTTP/3
        //
        3000 => Version::HTTP_3,


        //
        // Default fallback.
        //
        // nginx normally exposes only supported protocol
        // versions, but the converter must always return
        // a valid http::Version.
        //
        _ => Version::HTTP_11,
    }
}