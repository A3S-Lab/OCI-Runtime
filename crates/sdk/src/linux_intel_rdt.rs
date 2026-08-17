/// Maximum UTF-8 byte length accepted for an Intel RDT CLOS directory name.
pub const OCI_LINUX_INTEL_RDT_MAX_CLOS_ID_BYTES: usize = 255;
/// Maximum number of complete schemata lines accepted in one configuration.
pub const OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINES: usize = 256;
/// Maximum UTF-8 byte length accepted for one resctrl schemata line.
pub const OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_LINE_BYTES: usize = 4 * 1024;
/// Maximum encoded size accepted across every configured schemata write.
pub const OCI_LINUX_INTEL_RDT_MAX_SCHEMATA_BYTES: usize = 64 * 1024;
