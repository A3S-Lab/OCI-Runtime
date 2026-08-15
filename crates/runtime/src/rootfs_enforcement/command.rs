use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy)]
pub(super) struct NativeIdmapBindPaths<'a> {
    pub(super) source: &'a str,
    pub(super) foreign_readonly: &'a str,
    pub(super) idmap: &'a str,
    pub(super) ridmap: &'a str,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct EnforcementCommandPaths<'a> {
    pub(super) evidence: &'a str,
    pub(super) tmpfs_target: &'a str,
    pub(super) file_target: &'a str,
    pub(super) recursive_source: &'a str,
    pub(super) recursive_target: &'a str,
    pub(super) idmap_target: &'a str,
    pub(super) ridmap_target: &'a str,
    pub(super) write_probe: &'a str,
}

pub(super) fn enforcement_command(
    paths: EnforcementCommandPaths<'_>,
    native_idmap_bind: Option<NativeIdmapBindPaths<'_>>,
) -> String {
    let EnforcementCommandPaths {
        evidence,
        tmpfs_target,
        file_target,
        recursive_source,
        recursive_target,
        idmap_target,
        ridmap_target,
        write_probe,
    } = paths;
    let recursive_source_child = format!("{recursive_source}/child");
    let recursive_target_child = format!("{recursive_target}/child");
    let native_idmap_bind_checks = native_idmap_bind.map_or_else(String::new, |paths| {
        let source_child = format!("{}/child", paths.source);
        let idmap_child = format!("{}/child", paths.idmap);
        let ridmap_child = format!("{}/child", paths.ridmap);
        format!(
            "test \"$(/bin/busybox stat -c '%u:%g' '{source}')\" = '0:0'; \
             test \"$(/bin/busybox stat -c '%u:%g' '{source_child}')\" = '0:0'; \
             /bin/busybox awk '$5 == \"{source_child}\" {{ ok = 1 }} \
               END {{ exit !ok }}' /proc/self/mountinfo; \
             printf 'idmap-source-ownership-unchanged\\n' >> \"$evidence\"; \
             test \"$(/bin/busybox cat '{foreign_readonly}')\" = \
               'a3s-oci-foreign-readonly-bind-v1'; \
             test \"$(/bin/busybox stat -c '%a' '{foreign_readonly}')\" = '400'; \
             /bin/busybox awk '$5 == \"{foreign_readonly}\" && \
               $6 ~ /(^|,)ro(,|$)/ && $6 ~ /(^|,)nosuid(,|$)/ && \
               $6 ~ /(^|,)nodev(,|$)/ && $6 ~ /(^|,)noexec(,|$)/ \
               {{ ok = 1 }} END {{ exit !ok }}' /proc/self/mountinfo; \
             if printf 'forbidden\\n' > '{foreign_readonly}' 2>/dev/null; then \
               exit 46; fi; \
             printf 'foreign-readonly-bind-enforced\\n' >> \"$evidence\"; \
             test \"$(/bin/busybox stat -c '%u:%g' '{idmap}')\" = '1000:1000'; \
             test \"$(/bin/busybox stat -c '%u:%g' '{idmap_child}')\" = '0:0'; \
             /bin/busybox awk '$5 == \"{idmap_child}\" {{ ok = 1 }} \
               END {{ exit !ok }}' /proc/self/mountinfo; \
             printf 'idmap-nonrecursive-enforced\\n' >> \"$evidence\"; \
             test \"$(/bin/busybox stat -c '%u:%g' '{ridmap}')\" = '2000:2000'; \
             test \"$(/bin/busybox stat -c '%u:%g' '{ridmap_child}')\" = '2000:2000'; \
             /bin/busybox awk '$5 == \"{ridmap_child}\" {{ ok = 1 }} \
               END {{ exit !ok }}' /proc/self/mountinfo; \
             printf 'ridmap-recursive-enforced\\n' >> \"$evidence\"; ",
            source = paths.source,
            foreign_readonly = paths.foreign_readonly,
            idmap = paths.idmap,
            ridmap = paths.ridmap,
        )
    });
    format!(
        "set -eu; \
         evidence='{evidence}'; \
         : > \"$evidence\"; \
         failure_step=pid-self; \
         failure_detail=none; \
         trap 'status=$?; if test \"$status\" -ne 0; then \
           printf \"failure-step=%s status=%s detail=%s\\n\" \
             \"$failure_step\" \"$status\" \"$failure_detail\" >> \"$evidence\"; \
           fi; exit \"$status\"' EXIT; \
         self_pid=$$; \
         test \"$self_pid\" -gt 1; \
         failure_step=pid-parent; \
         test \"$(/bin/busybox awk '/^PPid:/ {{ print $2 }}' \
           \"/proc/$self_pid/status\")\" = '1'; \
         failure_step=pid-init-nspid; \
         test \"$(/bin/busybox awk '/^NSpid:/ {{ print $NF }}' /proc/1/status)\" = '1'; \
         failure_step=pid-init-parent; \
         test \"$(/bin/busybox awk '/^PPid:/ {{ print $2 }}' /proc/1/status)\" = '0'; \
         failure_step=pid-self-nspid; \
         test \"$(/bin/busybox awk '/^NSpid:/ {{ print $NF }}' \
           \"/proc/$self_pid/status\")\" = \
           \"$self_pid\"; \
         printf 'pid1-supervision-enforced\\n' >> \"$evidence\"; \
         failure_step=orphan-supervision; \
         failure_detail=none; \
         orphan_pid_file=\"${{evidence}}.orphan-pid\"; \
         /bin/busybox rm -f \"$orphan_pid_file\"; \
         /bin/busybox setsid /bin/busybox setsid /bin/busybox sh -c \
           'set -eu; printf \"%s\\n\" \"$$\" > \"$1\"; \
              exec /bin/busybox sleep 30' \
           a3s-orphan-child \"$orphan_pid_file\"; \
         attempt=0; \
         while test ! -s \"$orphan_pid_file\" && test \"$attempt\" -lt 100; do \
           /bin/busybox sleep 0.01; attempt=$((attempt + 1)); \
         done; \
         test -s \"$orphan_pid_file\"; \
         orphan_pid=\"$(/bin/busybox cat \"$orphan_pid_file\")\"; \
         if ! test \"$orphan_pid\" -gt 1; then \
           printf 'invalid-orphan-pid=%s\\n' \"$orphan_pid\" >> \"$evidence\"; exit 45; \
         fi; \
         orphan_parent=''; attempt=0; \
         while test \"$attempt\" -lt 100; do \
           if test -e \"/proc/$orphan_pid/status\"; then \
             orphan_parent=\"$(/bin/busybox awk '/^PPid:/ {{ print $2 }}' \
               \"/proc/$orphan_pid/status\")\"; \
             if test \"$orphan_parent\" = '1'; then break; fi; \
           fi; \
           /bin/busybox sleep 0.01; \
           attempt=$((attempt + 1)); \
         done; \
         if test \"$orphan_parent\" != '1'; then \
           printf 'unexpected-orphan-parent=%s pid=%s self=%s\\n' \
             \"$orphan_parent\" \"$orphan_pid\" \"$self_pid\" >> \"$evidence\"; \
           /bin/busybox ps -o pid,ppid,comm >> \"$evidence\"; \
           exit 45; \
         fi; \
         printf 'orphan-adopted-by-pid1\\n' >> \"$evidence\"; \
         /bin/busybox kill -TERM \"$orphan_pid\"; \
         orphan_reaped=0; attempt=0; \
         while test \"$attempt\" -lt 400; do \
           if test ! -e \"/proc/$orphan_pid/status\"; then \
             orphan_reaped=1; break; \
           fi; \
           /bin/busybox sleep 0.01; \
           attempt=$((attempt + 1)); \
         done; \
         /bin/busybox rm -f \"$orphan_pid_file\"; \
         if test \"$orphan_reaped\" != '1'; then \
           /bin/busybox awk '/^(State|PPid|NSpid):/' \"/proc/$orphan_pid/status\" \
             >> \"$evidence\"; \
           exit 45; \
         fi; \
         printf 'orphan-reaping-enforced\\n' >> \"$evidence\"; \
         failure_step=dev-symlinks; \
         test -e /proc/self/fd; \
         test -e /proc/self/fd/0; \
         test -e /proc/self/fd/1; \
         test -e /proc/self/fd/2; \
         /bin/busybox awk '$5 == \"/dev\" {{ ok = 1 }} END {{ exit !ok }}' \
           /proc/self/mountinfo; \
         test \"$(/bin/busybox readlink /dev/fd)\" = '/proc/self/fd'; \
         test \"$(/bin/busybox readlink /dev/stdin)\" = '/proc/self/fd/0'; \
         test \"$(/bin/busybox readlink /dev/stdout)\" = '/proc/self/fd/1'; \
         test \"$(/bin/busybox readlink /dev/stderr)\" = '/proc/self/fd/2'; \
         printf 'dev-symlinks-verified\\n' >> \"$evidence\"; \
         test -d '{tmpfs_target}'; \
         /bin/busybox awk '$5 == \"{tmpfs_target}\" {{ ok = 1 }} END {{ exit !ok }}' \
           /proc/self/mountinfo; \
         printf 'mount-target-created\\n' >> \"$evidence\"; \
         test -f '{file_target}'; \
         test \"$(/bin/busybox cat '{file_target}')\" = 'a3s-oci-bind-source-v1'; \
         /bin/busybox awk '$5 == \"{file_target}\" {{ ok = 1 }} END {{ exit !ok }}' \
           /proc/self/mountinfo; \
         printf 'mount-file-target-created\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/\" {{ for (i = 7; i <= NF && $i != \"-\"; i++) \
           if ($i ~ /^shared:/) ok = 1 }} END {{ exit !ok }}' /proc/self/mountinfo; \
         printf 'rootfs-propagation-shared\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/proc/sys\" && $6 ~ /(^|,)ro(,|$)/ {{ ok = 1 }} \
           END {{ exit !ok }}' /proc/self/mountinfo; \
         printf 'readonly-path-enforced\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/proc/meminfo\" && $6 ~ /(^|,)ro(,|$)/ {{ ok = 1 }} \
           END {{ exit !ok }}' /proc/self/mountinfo; \
         test -f /proc/meminfo; test ! -s /proc/meminfo; \
         test -z \"$(/bin/busybox cat /proc/meminfo)\"; \
         printf 'masked-file-empty-readonly\\n' >> \"$evidence\"; \
         /bin/busybox awk '$5 == \"/proc/irq\" && $6 ~ /(^|,)ro(,|$)/ {{ ok = 1 }} \
           END {{ exit !ok }}' /proc/self/mountinfo; \
         test -d /proc/irq; test -z \"$(/bin/busybox ls -A /proc/irq)\"; \
         printf 'masked-directory-empty-readonly\\n' >> \"$evidence\"; \
         printf 'masked-path-enforced\\n' >> \"$evidence\"; \
         for path in '{recursive_target}' '{recursive_target_child}'; do \
           /bin/busybox awk -v path=\"$path\" '$5 == path && \
             $6 ~ /(^|,)ro(,|$)/ && $6 ~ /(^|,)nosuid(,|$)/ && \
             $6 ~ /(^|,)nodev(,|$)/ && $6 ~ /(^|,)noexec(,|$)/ && \
             $6 ~ /(^|,)noatime(,|$)/ && $6 ~ /(^|,)nodiratime(,|$)/ && \
             $6 ~ /(^|,)nosymfollow(,|$)/ {{ ok = 1 }} END {{ exit !ok }}' \
             /proc/self/mountinfo; \
         done; \
         for path in '{recursive_source}' '{recursive_source_child}'; do \
           /bin/busybox touch \"$path/write-probe\"; \
           /bin/busybox rm \"$path/write-probe\"; \
           printf '#!/bin/sh\\nexit 0\\n' > \"$path/exec-probe\"; \
           /bin/busybox chmod 0700 \"$path/exec-probe\"; \
           \"$path/exec-probe\"; \
           printf 'symlink-source\\n' > \"$path/symlink-source\"; \
           /bin/busybox ln -s symlink-source \"$path/symlink-probe\"; \
         done; \
         for path in '{recursive_target}' '{recursive_target_child}'; do \
           if /bin/busybox touch \"$path/write-probe\" 2>/dev/null; then exit 42; fi; \
           if \"$path/exec-probe\" 2>/dev/null; then exit 43; fi; \
           if /bin/busybox cat \"$path/symlink-probe\" >/dev/null 2>&1; then exit 44; fi; \
         done; \
         printf 'recursive-mount-attributes-enforced\\n' >> \"$evidence\"; \
         test \"$(/bin/busybox stat -c '%u:%g' '{idmap_target}')\" = '1000:1000'; \
         test \"$(/bin/busybox stat -c '%u:%g' '{ridmap_target}')\" = '2000:2000'; \
         printf 'idmapped-mounts-enforced\\n' >> \"$evidence\"; \
         {native_idmap_bind_checks}\
         /bin/busybox awk '$5 == \"/\" && $6 ~ /(^|,)ro(,|$)/ {{ ok = 1 }} \
           END {{ exit !ok }}' /proc/self/mountinfo; \
         if /bin/busybox touch '{write_probe}' 2>/dev/null; then \
           /bin/busybox rm -f '{write_probe}'; exit 41; \
         fi; \
         printf 'readonly-rootfs-enforced\\n' >> \"$evidence\"; \
         trap - EXIT"
    )
}

pub(super) fn process_command_mut(root: &mut Map<String, Value>) -> Result<&mut String, String> {
    let command = root
        .get_mut("process")
        .and_then(Value::as_object_mut)
        .and_then(|process| process.get_mut("args"))
        .and_then(Value::as_array_mut)
        .and_then(|args| args.get_mut(2))
        .ok_or_else(|| {
            "rootfs enforcement fixture requires process.args[2] to be a shell command".to_string()
        })?;
    command.as_str().ok_or_else(|| {
        "rootfs enforcement fixture requires process.args[2] to be a string".to_string()
    })?;
    match command {
        Value::String(command) => Ok(command),
        _ => Err("rootfs enforcement process command is not a string".into()),
    }
}
