#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CgroupSettingReadback {
    Exact,
    KernelDefined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CgroupSetting {
    file: String,
    value: String,
    readback: CgroupSettingReadback,
}

impl CgroupSetting {
    pub(super) fn new(file: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            value: value.into(),
            readback: CgroupSettingReadback::Exact,
        }
    }

    pub(super) fn kernel_defined(file: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            value: value.into(),
            readback: CgroupSettingReadback::KernelDefined,
        }
    }

    pub(super) fn file(&self) -> &str {
        &self.file
    }

    pub(super) fn value(&self) -> &str {
        &self.value
    }

    pub(super) fn readback(&self) -> CgroupSettingReadback {
        self.readback
    }

    pub(super) fn into_parts(self) -> (String, String, CgroupSettingReadback) {
        (self.file, self.value, self.readback)
    }
}

#[cfg(test)]
impl<'a> PartialEq<(&'a str, String)> for CgroupSetting {
    fn eq(&self, other: &(&'a str, String)) -> bool {
        self.file == other.0 && self.value == other.1
    }
}
