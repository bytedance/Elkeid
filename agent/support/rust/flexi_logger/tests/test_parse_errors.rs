use flexi_logger::{FlexiLoggerError, LogSpecification, Logger};
use log::*;

#[test]
fn parse_errors_logspec() {
    match LogSpecification::parse("info, foo=bar, fuzz=debug")
        .err()
        .unwrap()
    {
        FlexiLoggerError::Parse(_, logspec) => {
            assert_eq!(
                logspec.module_filters(),
                LogSpecification::parse("info, fuzz=debug")
                    .unwrap()
                    .module_filters()
            );
            #[cfg(feature = "textfilter")]
            assert!(logspec.text_filter().is_none());
        }
        _ => panic!("Wrong error from parsing (1)"),
    }

    match LogSpecification::parse("info, ene mene dubbedene")
        .err()
        .unwrap()
    {
        FlexiLoggerError::Parse(_, logspec) => {
            assert_eq!(
                logspec.module_filters(),
                LogSpecification::parse("info").unwrap().module_filters()
            );
            #[cfg(feature = "textfilter")]
            assert!(logspec.text_filter().is_none());
        }
        _ => panic!("Wrong error from parsing (2)"),
    }

    match LogSpecification::parse("ene mene dubbedene").err().unwrap() {
        FlexiLoggerError::Parse(_, logspec) => {
            assert_eq!(
                logspec.module_filters(),
                LogSpecification::off().module_filters()
            );
            #[cfg(feature = "textfilter")]
            assert!(logspec.text_filter().is_none());
        }
        _ => panic!("Wrong error from parsing (3)"),
    }

    match LogSpecification::parse("INFO, ene / mene / dubbedene")
        .err()
        .unwrap()
    {
        FlexiLoggerError::Parse(_, logspec) => {
            assert_eq!(
                logspec.module_filters(),
                LogSpecification::off().module_filters()
            );
            #[cfg(feature = "textfilter")]
            assert!(logspec.text_filter().is_none());
        }
        _ => panic!("Wrong error from parsing (4)"),
    }
}

#[test]
fn parse_errors_logger() {
    let result = Logger::with_str("info, foo=baz").check_parser_error();
    assert!(result.is_err());
    let error = result.err().unwrap();
    println!("err: {}", error);

    Logger::with_str("info, foo=debug")
        .check_parser_error()
        .unwrap()
        .start()
        .unwrap();
    info!("logging works");
    info!("logging works");
}
