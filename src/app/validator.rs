// std
#[allow(unused_imports)]
use std::ascii::AsciiExt;

// Internal
use INTERNAL_ERROR_MSG;
use INVALID_UTF8;
use app::parser::{ParseResult, Parser};
use app::settings::AppSettings as AS;
use app::usage::Usage;
use args::{Arg, ArgMatcher, MatchedArg};
use args::settings::ArgSettings;
use errors::{Error, ErrorKind};
use errors::Result as ClapResult;
use fmt::{Colorizer, ColorizerOption};
use osstringext::OsStrExt2;

pub struct Validator<'a, 'b, 'c, 'z>(&'z mut Parser<'a, 'b, 'c>)
where
    'a: 'b,
    'b: 'c,
    'c: 'z;

impl<'a, 'b, 'c, 'z> Validator<'a, 'b, 'c, 'z> {
    pub fn new(p: &'z mut Parser<'a, 'b, 'c>) -> Self { Validator(p) }

    pub fn validate(
        &mut self,
        needs_val_of: ParseResult<'a>,
        subcmd_name: Option<String>,
        matcher: &mut ArgMatcher<'a>,
    ) -> ClapResult<()> {
        debugln!("Validator::validate;");
        let mut reqs_validated = false;
        self.0.add_env(matcher)?;
        self.0.add_defaults(matcher)?;
        if let ParseResult::Opt(a) = needs_val_of {
            debugln!("Validator::validate: needs_val_of={:?}", a);
            let o = find!(self.0.app, &a).expect(INTERNAL_ERROR_MSG).clone();
            self.validate_required(matcher)?;
            reqs_validated = true;
            let should_err = if let Some(v) = matcher.0.args.get(&*o.name) {
                v.vals.is_empty() && !(o.min_vals.is_some() && o.min_vals.unwrap() == 0)
            } else {
                true
            };
            if should_err {
                for arg in &*matcher.get_used(self.0.app) {
                    self.0.required.push(arg);
                }
                return Err(Error::empty_value(
                    &o,
                    &*Usage::new(self.0).create_usage_with_title(),
                    self.0.app.color(),
                ));
            }
        }

        if matcher.is_empty() && matcher.subcommand_name().is_none()
            && self.0.is_set(AS::ArgRequiredElseHelp)
        {
            let mut out = vec![];
            self.0.write_help_err(&mut out)?;
            return Err(Error {
                message: String::from_utf8_lossy(&*out).into_owned(),
                kind: ErrorKind::MissingArgumentOrSubcommand,
                info: None,
            });
        }
        self.validate_blacklist(matcher)?;
        if !(self.0.is_set(AS::SubcommandsNegateReqs) && subcmd_name.is_some()) && !reqs_validated {
            self.validate_required(matcher)?;
        }
        self.validate_matched_args(matcher)?;
        matcher.usage(Usage::new(self.0).create_help_usage_with_title());

        Ok(())
    }

    fn validate_arg_values(
        &self,
        arg: &Arg,
        ma: &MatchedArg,
        matcher: &ArgMatcher<'a>,
    ) -> ClapResult<()> {
        debugln!("Validator::validate_arg_values: arg={:?}", arg.name);
        for val in &ma.vals {
            if self.0.is_set(AS::StrictUtf8) && val.to_str().is_none() {
                debugln!(
                    "Validator::validate_arg_values: invalid UTF-8 found in val {:?}",
                    val
                );
                for arg in &*matcher.get_used(self.0.app) {
                    self.0.required.push(arg);
                }
                return Err(Error::invalid_utf8(
                    &*Usage::new(self.0).create_usage_with_title(),
                    self.0.app.color(),
                ));
            }
            if let Some(ref p_vals) = arg.possible_vals {
                debugln!("Validator::validate_arg_values: possible_vals={:?}", p_vals);
                let val_str = val.to_string_lossy();
                let ok = if arg.is_set(ArgSettings::IgnoreCase) {
                    p_vals.iter().any(|pv| pv.eq_ignore_ascii_case(&*val_str))
                } else {
                    p_vals.contains(&&*val_str)
                };
                if !ok {
                    for arg in &*matcher.get_used(self.0.app) {
                        self.0.required.push(arg);
                    }
                    return Err(Error::invalid_value(
                        val_str,
                        p_vals,
                        arg,
                        &*Usage::new(self.0).create_usage_with_title(),
                        self.0.app.color(),
                    ));
                }
            }
            if !arg.is_set(ArgSettings::AllowEmptyValues) && val.is_empty_()
                && matcher.contains(&*arg.name)
            {
                debugln!("Validator::validate_arg_values: illegal empty val found");
                for arg in &*matcher.get_used(self.0.app) {
                    self.0.required.push(arg);
                }
                return Err(Error::empty_value(
                    arg,
                    &*Usage::new(self.0).create_usage_with_title(),
                    self.0.app.color(),
                ));
            }
            if let Some(ref vtor) = arg.validator {
                debug!("Validator::validate_arg_values: checking validator...");
                if let Err(e) = vtor(val.to_string_lossy().into_owned()) {
                    sdebugln!("error");
                    return Err(Error::value_validation(Some(arg), e, self.0.app.color()));
                } else {
                    sdebugln!("good");
                }
            }
            if let Some(ref vtor) = arg.validator_os {
                debug!("Validator::validate_arg_values: checking validator_os...");
                if let Err(e) = vtor(val) {
                    sdebugln!("error");
                    return Err(Error::value_validation(
                        Some(arg),
                        (*e).to_string_lossy().to_string(),
                        self.0.app.color(),
                    ));
                } else {
                    sdebugln!("good");
                }
            }
        }
        Ok(())
    }

    fn build_conflict_err(&self, name: &str, matcher: &ArgMatcher<'a>) -> ClapResult<()> {
        debugln!("build_err!: name={}", name);
        let mut c_with = find_from!(self.0.app, &name, blacklist, &matcher);
        c_with = c_with.or(find!(self.0.app, &name)
            .map_or(None, |ref aa| aa.blacklist.as_ref())
            .map_or(None, |ref bl| bl.iter().find(|arg| matcher.contains(arg)))
            .map_or(None, |an| find!(self.0.app, an))
            .map_or(None, |aa| Some(format!("{}", aa))));
        debugln!("build_err!: '{:?}' conflicts with '{}'", c_with, &name);
        //        matcher.remove(&name);
        for arg in &*matcher.get_used(self.0.app) {
            self.0.required.push(arg);
        }
        let usg = &*Usage::new(self.0).create_usage_with_title();
        if let Some(f) = find!(self.0.app, &name) {
            debugln!("build_err!: It was a flag...");
            Err(Error::argument_conflict(
                f,
                c_with,
                &*usg,
                self.0.app.color(),
            ))
        } else {
            panic!(INTERNAL_ERROR_MSG);
        }
    }

    fn validate_blacklist(&self, matcher: &mut ArgMatcher<'a>) -> ClapResult<()> {
        debugln!("Validator::validate_blacklist;");
        for name in &self.gather_conflicts(matcher) {
            debugln!("Validator::validate_blacklist:iter:{};", name);
            let mut should_err = false;
            if groups!(self.0.app).any(|g| &g.name == name) {
                debugln!("Validator::validate_blacklist:iter:{}:group;", name);
                for n in self.0.arg_names_in_group(name) {
                    debugln!(
                        "Validator::validate_blacklist:iter:{}:group:iter:{};",
                        name,
                        n
                    );
                    if matcher.contains(n) {
                        debugln!(
                            "Validator::validate_blacklist:iter:{}:group:iter:{}: found;",
                            name,
                            n
                        );
                        return self.build_conflict_err(n, matcher);
                    }
                }
            } else if let Some(ma) = matcher.get(name) {
                debugln!(
                    "Validator::validate_blacklist:iter:{}: matcher contains it...",
                    name
                );
                should_err = ma.occurs > 0;
            }
            if should_err {
                return self.build_conflict_err(*name, matcher);
            }
        }
        Ok(())
    }

    fn gather_conflicts(&self, matcher: &mut ArgMatcher<'a>) -> Vec<&'a str> {
        debugln!("Validator::gather_conflicts;");
        let mut conflicts = vec![];
        for name in matcher.arg_names() {
            debugln!("Validator::gather_conflicts:iter:{};", name);
            if let Some(arg) = find!(self.0.app, name) {
                if let Some(ref bl) = arg.blacklist {
                    for conf in bl {
                        if matcher.get(conf).is_some() {
                            conflicts.push(*conf);
                        }
                    }
                }
                if let Some(grps) = self.0.groups_for_arg(name) {
                    for grp in &grps {
                        if let Some(g) = find!(self.0.app, grp, groups) {
                            if !g.multiple {
                                for g_arg in &g.args {
                                    if &g_arg == &name {
                                        continue;
                                    }
                                    conflicts.push(g_arg);
                                }
                            }
                            if let Some(ref gc) = g.conflicts {
                                conflicts.extend(&*gc);
                            }
                        }
                    }
                }
            } else {
                debugln!("Validator::gather_conflicts:iter:{}:group;", name);
                let args = self.0.arg_names_in_group(name);
                for arg in &args {
                    debugln!(
                        "Validator::gather_conflicts:iter:{}:group:iter:{};",
                        name,
                        arg
                    );
                    if let Some(ref bl) =
                        find!(self.0.app, arg).expect(INTERNAL_ERROR_MSG).blacklist
                    {
                        for conf in bl {
                            if matcher.get(conf).is_some() {
                                conflicts.push(conf);
                            }
                        }
                    }
                }
            }
        }
        conflicts
    }

    fn validate_matched_args(&self, matcher: &mut ArgMatcher<'a>) -> ClapResult<()> {
        debugln!("Validator::validate_matched_args;");
        for (name, ma) in matcher.iter() {
            debugln!(
                "Validator::validate_matched_args:iter:{}: vals={:#?}",
                name,
                ma.vals
            );
            if let Some(arg) = find!(self.0.app, name) {
                self.validate_arg_num_vals(arg, ma, matcher)?;
                self.validate_arg_values(arg, ma, matcher)?;
                self.validate_arg_requires(arg, ma, matcher)?;
                self.validate_arg_num_occurs(arg, ma, matcher)?;
            } else {
                let grp = find!(self.0.app, name, groups).expect(INTERNAL_ERROR_MSG);
                if let Some(ref g_reqs) = grp.requires {
                    if g_reqs.iter().any(|&n| !matcher.contains(n)) {
                        return self.missing_required_error(matcher, None);
                    }
                }
                for arg in &*matcher.get_used(self.0.app) {
                    self.0.required.push(arg);
                }
            }
        }
        Ok(())
    }

    fn validate_arg_num_occurs(
        &self,
        a: &Arg,
        ma: &MatchedArg,
        matcher: &ArgMatcher<'a>,
    ) -> ClapResult<()> {
        debugln!("Validator::validate_arg_num_occurs: a={};", a.name);
        if ma.occurs > 1 && !a.is_set(ArgSettings::MultipleOccurrences) {
            // Not the first time, and we don't allow multiples
            for arg in &*matcher.get_used(self.0.app) {
                self.0.required.push(arg);
            }
            return Err(Error::unexpected_multiple_usage(
                a,
                &*Usage::new(self.0).create_usage_with_title(),
                self.0.app.color(),
            ));
        }
        Ok(())
    }

    fn validate_arg_num_vals(
        &self,
        a: &Arg,
        ma: &MatchedArg,
        matcher: &ArgMatcher<'a>,
    ) -> ClapResult<()> {
        debugln!("Validator::validate_arg_num_vals;");
        if let Some(num) = a.num_vals {
            debugln!("Validator::validate_arg_num_vals: num_vals set...{}", num);
            let should_err = if a.is_set(ArgSettings::MultipleValues) {
                ((ma.vals.len() as u64) % num) != 0
            } else {
                num != (ma.vals.len() as u64)
            };
            if should_err {
                debugln!("Validator::validate_arg_num_vals: Sending error WrongNumberOfValues");
                for arg in &*matcher.get_used(self.0.app) {
                    self.0.required.push(arg);
                }
                return Err(Error::wrong_number_of_values(
                    a,
                    num,
                    if a.is_set(ArgSettings::MultipleValues) {
                        (ma.vals.len() % num as usize)
                    } else {
                        ma.vals.len()
                    },
                    if ma.vals.len() == 1
                        || (a.is_set(ArgSettings::MultipleValues)
                            && (ma.vals.len() % num as usize) == 1)
                    {
                        "as"
                    } else {
                        "ere"
                    },
                    &*Usage::new(self.0).create_usage_with_title(),
                    self.0.app.color(),
                ));
            }
        }
        if let Some(num) = a.max_vals {
            debugln!("Validator::validate_arg_num_vals: max_vals set...{}", num);
            if (ma.vals.len() as u64) > num {
                debugln!("Validator::validate_arg_num_vals: Sending error TooManyValues");
                for arg in &*matcher.get_used(self.0.app) {
                    self.0.required.push(arg);
                }
                return Err(Error::too_many_values(
                    ma.vals
                        .iter()
                        .last()
                        .expect(INTERNAL_ERROR_MSG)
                        .to_str()
                        .expect(INVALID_UTF8),
                    a,
                    &*Usage::new(self.0).create_usage_with_title(),
                    self.0.app.color(),
                ));
            }
        }
        let min_vals_zero = if let Some(num) = a.min_vals {
            debugln!("Validator::validate_arg_num_vals: min_vals set: {}", num);
            if (ma.vals.len() as u64) < num && num != 0 {
                debugln!("Validator::validate_arg_num_vals: Sending error TooFewValues");
                for arg in &*matcher.get_used(self.0.app) {
                    self.0.required.push(arg);
                }
                return Err(Error::too_few_values(
                    a,
                    num,
                    ma.vals.len(),
                    &*Usage::new(self.0).create_usage_with_title(),
                    self.0.app.color(),
                ));
            }
            num == 0
        } else {
            false
        };
        // Issue 665 (https://github.com/kbknapp/clap-rs/issues/665)
        // Issue 1105 (https://github.com/kbknapp/clap-rs/issues/1105)
        if a.is_set(ArgSettings::TakesValue) && !min_vals_zero && ma.vals.is_empty() {
            for arg in &*matcher.get_used(self.0.app) {
                self.0.required.push(arg);
            }
            return Err(Error::empty_value(
                a,
                &*Usage::new(self.0).create_usage_with_title(),
                self.0.app.color(),
            ));
        }
        Ok(())
    }

    fn validate_arg_requires(
        &self,
        a: &Arg,
        ma: &MatchedArg,
        matcher: &ArgMatcher<'a>,
    ) -> ClapResult<()> {
        debugln!("Validator::validate_arg_requires:{};", a.name);
        if let Some(ref a_reqs) = a.requires {
            // Conditional requirements
            for &(val, name) in a_reqs.iter().filter(|&&(val, _)| val.is_some()) {
                let missing_req =
                    |v| v == val.expect(INTERNAL_ERROR_MSG) && !matcher.contains(name);
                if ma.vals.iter().any(missing_req) {
                    return self.missing_required_error(matcher, None);
                }
            }

            // Other args required
            for &(_, name) in a_reqs.iter().filter(|&&(val, _)| val.is_none()) {
                if !matcher.contains(name) {
                    return self.missing_required_error(matcher, None);
                }
            }
        }
        Ok(())
    }

    fn validate_required(&mut self, matcher: &ArgMatcher<'a>) -> ClapResult<()> {
        debugln!(
            "Validator::validate_required: required={:?};",
            self.0.required
        );

        let mut should_err = false;
        let mut to_rem = Vec::new();
        // let mut sub_required = Vec::new();
        for &name in &self.0.required {
            debugln!("Validator::validate_required:iter:{}:", name);
            if let Some(a) = find!(self.0.app, &name) {
                let was_used = matcher.contains(name);
                if self.is_missing_required_ok(a, matcher) && !was_used {
                    debugln!(
                        "Validator::validate_required:iter:{}: was used or is ok to miss",
                        name
                    );
                    to_rem.push(name);
                    // if let Some(ref areqs) = a.requires {
                    // for name in areqs
                    //     .iter()
                    //     .filter(|&&(val, _)| val.is_none())
                    //     .map(|&(_, name)| name)
                    // {
                    //     to_rem.push(name);
                    // }
                    // }
                    continue;
                }
                if !was_used {
                    should_err = true;
                }
                // if let Some(ref areqs) = a.requires {
                //     for name in areqs
                //         .iter()
                //         .filter(|&&(val, _)| val.is_none())
                //         .map(|&(_, name)| name)
                //     {
                //         sub_required.push(name);
                //     }
                // }
            }
        }
        debugln!("Validator::validate_required:error: removing {:?}", to_rem);
        'to_rem: for r in &to_rem {
            'app_req: for i in (0..self.0.required.len()).rev() {
                if &self.0.required[i] == r {
                    self.0.required.swap_remove(i);
                    continue 'to_rem;
                }
            }
        }
        // debugln!(
        //     "Validator::validate_required:error: sub reqs found {:?}",
        //     sub_required
        // );
        // for r in sub_required.into_iter() {
        //     self.0.required.push(r);
        // }
        if should_err {
            return self.missing_required_error(matcher, None);
        }

        // Validate the conditionally required args
        for &(a, v, r) in &self.0.r_ifs {
            if let Some(ma) = matcher.get(a) {
                if matcher.get(r).is_none() && ma.vals.iter().any(|val| val == v) {
                    return self.missing_required_error(matcher, Some(r));
                }
            }
        }
        Ok(())
    }

    fn is_missing_required_ok(&self, a: &Arg<'a, 'b>, matcher: &ArgMatcher<'a>) -> bool {
        debugln!("Validator::is_missing_required_ok: a={}", a.name);
        self.validate_arg_conflicts(a, matcher).unwrap_or(false)
            || self.validate_required_unless(a, matcher).unwrap_or(false)
            || self.0.overriden.contains(&a.name)
    }

    fn validate_arg_conflicts(&self, a: &Arg<'a, 'b>, matcher: &ArgMatcher<'a>) -> Option<bool> {
        debugln!("Validator::validate_arg_conflicts: a={:?};", a.name);
        a.blacklist.as_ref().map(|bl| {
            bl.iter().any(|ref conf| {
                matcher.contains(conf)
                    || find!(self.0.app, *conf, groups)
                        .map_or(false, |g| g.args.iter().any(|arg| matcher.contains(arg)))
            })
        })
    }

    fn validate_required_unless(&self, a: &Arg<'a, 'b>, matcher: &ArgMatcher<'a>) -> Option<bool> {
        debugln!("Validator::validate_required_unless: a={:?};", a.name);
        macro_rules! check {
            ($how:ident, $_self:expr, $a:ident, $m:ident) => {{
                $a.r_unless.as_ref().map(|ru| {
                    ru.iter().$how(|n| {
                        $m.contains(n) || {
                            if let Some(grp) = find!($_self.app, n, groups) {
                                     grp.args.iter().any(|arg| $m.contains(arg))
                            } else {
                                false
                            }
                        }
                    })
                })
            }};
        }
        if a.is_set(ArgSettings::RequiredUnlessAll) {
            check!(all, self.0, a, matcher)
        } else {
            check!(any, self.0, a, matcher)
        }
    }

    fn missing_required_error(
        &self,
        matcher: &ArgMatcher<'a>,
        extra: Option<&'a str>,
    ) -> ClapResult<()> {
        debugln!("Validator::missing_required_error: extra={:?}", extra);
        let c = Colorizer::new(ColorizerOption {
            use_stderr: true,
            when: self.0.app.color(),
        });
        // @TODO @FIXME @P1 get_required_usage_from is turning the args into strings for display
        // we need them still in arg name form so we can skip ones that are already used
        // but then we need ALL of them for the usage string...so how?
        let reqs = self.0.get_required_unrolled(extra);
        debugln!("Validator::missing_required_error: reqs={:?}", reqs);
        let req_args = reqs.iter()
            .filter(|r| !matcher.contains(r))
            .fold(String::new(), |acc, s| {
                acc + &format!("\n    {}", c.error(s))[..]
            });
        Err(Error::missing_required_argument(
            &*req_args,
            &*format!(
                "USAGE:\n    {}",
                Usage::new(self.0).create_smart_usage_from_reqs(&reqs)
            ),
            self.0.app.color(),
        ))
    }
}
