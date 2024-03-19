use crate::HttpSigDomainInfo;
use indexmap::IndexMap;
use pulldown_cmark::{Event, HeadingLevel, Parser, Tag, TagEnd};
use std::borrow::Cow;

/// Parse the markdown
pub(crate) fn parse_md<'a, T: Into<Cow<'a, str>>>(markdown_input: T) -> Vec<HttpSigDomainInfo> {
  let markdown_input = markdown_input.into();
  let parser = Parser::new(markdown_input.as_ref());

  type VisitingState = Option<u8>;
  const VISITING_H2: u8 = 0;
  const VISITING_LIST: u8 = 1;
  const VISITING_ITEM: u8 = 2;
  let mut visiting_state: VisitingState = None;
  let mut visiting_domain: Option<String> = None;
  let mut domain_map: IndexMap<String, Vec<String>> = IndexMap::new();
  let mut textbuf = String::new();
  for event in parser {
    match event {
      Event::Start(Tag::Heading {
        level: HeadingLevel::H2, ..
      }) => {
        visiting_state = Some(VISITING_H2);
        visiting_domain = None;
        textbuf.clear();
      }
      Event::End(TagEnd::Heading(HeadingLevel::H2)) => {
        visiting_state = None;
      }
      Event::Start(Tag::List(_)) => {
        visiting_state = Some(VISITING_LIST);
        textbuf.clear();
      }
      Event::End(TagEnd::List(_)) => {
        visiting_state = None;
        visiting_domain = None;
        textbuf.clear();
      }
      Event::Start(Tag::Item) => {
        if matches!(visiting_state, Some(VISITING_LIST)) {
          visiting_state = Some(VISITING_ITEM);
          textbuf.clear();
        }
      }
      Event::End(TagEnd::Item) => {
        if matches!(visiting_state, Some(VISITING_ITEM)) {
          visiting_state = Some(VISITING_LIST);
          textbuf.clear();
        }
      }
      Event::Text(text) => match visiting_state {
        Some(VISITING_H2) => {
          visiting_domain = Some(text.to_string());
          domain_map.entry(text.trim().to_string()).or_default();
          textbuf.clear();
        }
        Some(VISITING_ITEM) => {
          if let Some(domain) = &visiting_domain {
            textbuf.push_str(&text);
            let text = text.trim().to_string();
            if text != "*" {
              domain_map.get_mut(domain).unwrap().push(textbuf.clone());
              textbuf.clear();
            }
          }
        }
        _ => (),
      },
      _ => (),
    }
  }
  let domain_info_vec = domain_map
    .iter_mut()
    .map(|(k, v)| if v.is_empty() { (k, vec![k.clone()]) } else { (k, v.clone()) })
    .flat_map(|(k, v)| {
      v.iter()
        .map(move |dh_target| HttpSigDomainInfo::new(k.clone(), Some(dh_target.clone())))
        .collect::<Vec<_>>()
    })
    .collect::<Vec<_>>();

  domain_info_vec
}
