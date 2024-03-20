use proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, punctuated::Punctuated, spanned::Spanned, DeriveInput, Expr, Fields, Token,
};

/// Derives a series of implementations of the `endure_lib::Metric::GetMetricValue`
/// for all enum variants.
///
/// This macro can be used to derive the implementations for enums with
/// variants having a single unnamed value each. Suppose there is an enum
/// like this:
///
/// ```
/// enum MetricValue {
///     Int64Value(i64),
///     StringValue(String)
/// }
/// ```
///
/// it will generate the following implementations:
///
/// ```
/// pub trait GetMetricValue<T> {
///     fn get_metric_value(&self) -> Option<T>;
/// }
///
/// enum MetricValue {
///     Int64Value(i64),
///     StringValue(String)
/// }
///
/// impl GetMetricValue<i64> for MetricValue {
///     fn get_metric_value(&self) -> Option<i64> {
///         match &self {
///             Self::Int64Value(v) => Some(v.clone()),
///             _ => None,
///         }
///     }
/// }
///
/// impl GetMetricValue<String> for MetricValue {
///     fn get_metric_value(&self) -> Option<String> {
///         match &self {
///             Self::StringValue(v) => Some(v.clone()),
///             _ => None,
///         }
///     }
/// }
/// ```
#[proc_macro_derive(GetMetricValue)]
pub fn derive_copy_into(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let mut impls: Vec<_> = vec![];
    // This macro can only be derived by enums.
    if let syn::Data::Enum(ref data) = input.data {
        // Iterate over the enum variants.
        for variant in data.variants.clone().into_iter() {
            // Variant must contain one field (e.g., `Int64Value(i64))` contains
            // one field `i64`.
            match variant.fields {
                // The fields must be unnamed in the enum.
                Fields::Unnamed(fields) => {
                    if fields.unnamed.len() != 1 {
                        return TokenStream::from(
                            syn::Error::new(
                                input.ident.span(),
                                "Enum variants must have exactly one value each when deriving `GetMetricValue`",
                            )
                            .to_compile_error(),
                        );
                    }
                    // Get the type of the field (e.g., `i64`).
                    let field_type = &fields.unnamed.first().unwrap().ty;
                    let name = variant.ident;
                    impls.push(quote!(
                    impl GetMetricValue<#field_type> for MetricValue {
                        fn get_metric_value(&self) -> Option<#field_type> {
                            match &self {
                                Self::#name(v) => Some(v.clone()),
                                _ => None,
                            }
                        }
                    }));
                }
                _ => return TokenStream::from(
                    syn::Error::new(
                        input.ident.span(),
                        "Enum variants must have an unnamed field when deriving `GetMetricValue`",
                    )
                    .to_compile_error(),
                ),
            }
        }
        // Create a single token stream from multiple streams, each holding
        // an implementation for one variant.
        return TokenStream::from(quote!(
            #(#impls)*
        ));
    }
    TokenStream::from(
        syn::Error::new(
            input.ident.span(),
            "Only enums with variants having a single value can derive `GetMetricValue`",
        )
        .to_compile_error(),
    )
}

/// A macro implementing the `FromMetricsStore` trait for an auditor.
///
/// It creates an auditor's instance using the [`Default`] implementation.
/// Next, it calls the `init_metrics` function for this instance to initialize
/// metrics used by the auditor in the metric store.
///
#[proc_macro_derive(FromMetricsStore)]
pub fn derive_from_metrics_store(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    TokenStream::from(quote!(
    impl FromMetricsStore for #name {
        fn from_metrics_store(metrics_store: &SharedMetricsStore) -> Self {
            let mut auditor: #name = Default::default();
            auditor.init_metrics(metrics_store);
            auditor
        }
    }))
}

/// A macro implementing the `AuditProfileCheck` trait.
///
/// This trait is implemented by the auditor and it returns the audit
/// profiles the auditor supports. The profiles designate the groups of
/// auditors enabled in the given configuration. For example, different
/// groups of auditors is executed for `pcap` analysis and different for
/// live packet analysis.
///
/// # Attributes
///
/// The `profiles` attribute holds a list of profiles for which the
/// auditors should be enabled.
///
#[proc_macro_derive(AuditProfileCheck, attributes(profiles))]
pub fn audit_profile_check(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    // Find the attribute that lists profiles.
    let profiles = input
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("profiles"));

    // If the attribute was found, parse the comma separated list of
    // profiles and store them in the vector.
    let mut parsed_profiles: Vec<_> = vec![];
    if let Some(profiles) = profiles {
        let args = profiles
            .parse_args_with(Punctuated::<Expr, Token![,]>::parse_terminated)
            .unwrap();
        for arg in args.iter() {
            parsed_profiles.push(quote!(#arg));
        }
    }
    let profiles_num = parsed_profiles.len();
    TokenStream::from(quote!(
    impl AuditProfileCheck for #name {
            fn has_audit_profile(audit_profile: &AuditProfile) -> bool {
                let supported_profiles: [AuditProfile; #profiles_num] = [#(#parsed_profiles),*];
                supported_profiles.contains(audit_profile.clone())
            }
    }))
}

/// A macro conditionally adding an auditor to the analyzer.
///
/// This macro eliminates a repeatitive code in the packet analyzer which
/// checks if the specified auditor should be installed for the particular
/// profile. The auditors must implement the `AuditProfileCheck` trait.
///
/// # Expected variables
///
/// The macro requires that the following variables exist in scope of the
/// function where it is called:
///
/// - `auditors` - a vector of auditors where the auditor is added when it
///   passes a profile check.
/// - `audit_profile` - an audit profile for which the profile checks are performed.
/// - `self.metrics_store` -  metrics store instance passed to the instantiated
///   auditors.
///
#[proc_macro]
pub fn cond_add_auditor(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input with Punctuated::<Expr, syn::Token![,]>::parse_terminated);

    if args.len() != 1 {
        return TokenStream::from(
            syn::Error::new(
                args.span(),
                "Incorrect number of arguments to the `cond_add_auditor` macro",
            )
            .to_compile_error(),
        );
    }
    let auditor_name = args.first().unwrap();

    TokenStream::from(quote!(
        if #auditor_name::has_audit_profile(audit_profile) {
            auditors.push(Box::new(#auditor_name::from_metrics_store(&self.metrics_store)));
        }
    ))
}
