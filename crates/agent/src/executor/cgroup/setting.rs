#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CgroupSetting {
    file: String,
    value: String,
}

impl CgroupSetting {
    pub(super) fn new(file: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            value: value.into(),
        }
    }

    pub(super) fn file(&self) -> &str {
        &self.file
    }

    pub(super) fn value(&self) -> &str {
        &self.value
    }

    pub(super) fn into_parts(self) -> (String, String) {
        (self.file, self.value)
    }
}

#[cfg(test)]
impl<'a> PartialEq<(&'a str, String)> for CgroupSetting {
    fn eq(&self, other: &(&'a str, String)) -> bool {
        self.file == other.0 && self.value == other.1
    }
}
