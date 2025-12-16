use http::Request;
use hyper::header::{
    HeaderMap, HeaderValue, 
    RANGE, IF_RANGE, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_MATCH, IF_UNMODIFIED_SINCE,
    ACCEPT, ACCEPT_ENCODING, ACCEPT_LANGUAGE, USER_AGENT, REFERER, HOST, 
    CONNECTION, CACHE_CONTROL, COOKIE, AUTHORIZATION, 
    CONTENT_TYPE, CONTENT_LENGTH, ORIGIN, ETAG, LAST_MODIFIED
};
use chrono::{DateTime, ParseResult, Utc, format::{Parsed, StrftimeItems}};
use std::{collections::HashMap, net::SocketAddr};

#[derive(Clone)]
pub struct HttpContext {
    // Common headers
    pub client_addr: SocketAddr,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub accept: Option<String>,
    pub accept_encoding: Option<String>,
    pub accept_language: Option<String>,
    pub connection: Option<String>,
    pub cache_control: Option<String>,
    pub cookie: Option<String>,
    pub authorization: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub referer: Option<String>,
    pub origin: Option<String>,
    
    // Range headers
    pub range: Option<RangeHeader>,
    pub if_range: Option<IfRangeHeader>,
    
    // Conditional headers
    pub if_modified_since: Option<DateTime<Utc>>,
    pub if_unmodified_since: Option<DateTime<Utc>>,
    pub if_none_match: Option<Vec<String>>,
    pub if_match: Option<Vec<String>>,
    
    // All other headers
    pub other_headers: HashMap<String, String>,
}

#[derive(Clone, PartialEq)]
pub struct RangeHeader {
    pub unit: String,
    pub ranges: Vec<RangeSpec>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RangeSpec {
    pub start: Option<u64>,
    pub end: Option<u64>,
}

#[derive(Clone, PartialEq)]
pub enum IfRangeHeader {
    ETag(String),
    Date(DateTime<Utc>),
}

impl std::fmt::Debug for HttpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpContext")
            .field("host", &self.host)
            .field("user_agent", &self.user_agent)
            .field("accept", &self.accept)
            .field("accept_encoding", &self.accept_encoding)
            .field("accept_language", &self.accept_language)
            .field("connection", &self.connection)
            .field("cache_control", &self.cache_control)
            .field("cookie", &self.cookie.as_ref().map(|_| "[PRESENT]"))
            .field("authorization", &self.authorization.as_ref().map(|_| "[PRESENT]"))
            .field("content_type", &self.content_type)
            .field("content_length", &self.content_length)
            .field("referer", &self.referer)
            .field("origin", &self.origin)
            .field("range", &self.range)
            .field("if_range", &self.if_range)
            .field("if_modified_since", &self.if_modified_since)
            .field("if_unmodified_since", &self.if_unmodified_since)
            .field("if_none_match", &self.if_none_match)
            .field("if_match", &self.if_match)
            .field("other_headers_count", &self.other_headers.len())
            .finish()
    }
}

impl std::fmt::Debug for IfRangeHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IfRangeHeader::ETag(etag) => write!(f, "IfRangeHeader::ETag(\"{}\")", etag),
            IfRangeHeader::Date(date) => {
                write!(f, "IfRangeHeader::Date({})", date.format("%Y-%m-%d %H:%M:%S"))
            }
        }
    }
}

impl std::fmt::Debug for RangeHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RangeHeader {{ unit: {}, ranges: [", self.unit)?;
        for (i, range) in self.ranges.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            match (range.start, range.end) {
                (Some(s), Some(e)) => write!(f, "{}-{}", s, e)?,
                (Some(s), None) => write!(f, "{}-", s)?,
                (None, Some(e)) => write!(f, "-{}", e)?,
                (None, None) => write!(f, "invalid")?,
            }
        }
        write!(f, "] }}")
    }
}


impl HttpContext {
    pub fn from_request<T>(req: &Request<T>, client_addr: SocketAddr) -> Self 
    {
        Self::from_headers(req.headers(), client_addr)
    }
    
    pub fn from_headers(headers: &HeaderMap, client_addr: SocketAddr) -> Self {
        let mut client_headers = HttpContext {
            client_addr,
            host: get_header_str(headers, HOST),
            user_agent: get_header_str(headers, USER_AGENT),
            accept: get_header_str(headers, ACCEPT),
            accept_encoding: get_header_str(headers, ACCEPT_ENCODING),
            accept_language: get_header_str(headers, ACCEPT_LANGUAGE),
            connection: get_header_str(headers, CONNECTION),
            cache_control: get_header_str(headers, CACHE_CONTROL),
            cookie: get_header_str(headers, COOKIE),
            authorization: get_header_str(headers, AUTHORIZATION),
            content_type: get_header_str(headers, CONTENT_TYPE),
            content_length: get_header_u64(headers, CONTENT_LENGTH),
            referer: get_header_str(headers, REFERER),
            origin: get_header_str(headers, ORIGIN),
            
            // Range headers
            range: parse_range_header(headers),
            if_range: parse_if_range_header(headers),
            
            // Conditional headers
            if_modified_since: parse_date_header(headers, IF_MODIFIED_SINCE),
            if_unmodified_since: parse_date_header(headers, IF_UNMODIFIED_SINCE),
            if_none_match: parse_etag_list(headers, IF_NONE_MATCH),
            if_match: parse_etag_list(headers, IF_MATCH),
            
            other_headers: HashMap::new(),
        };
        
        // Collect all other headers
        for (key, value) in headers.iter() {
            let key_str = key.as_str().to_lowercase();
            let value_str = value.to_str().unwrap_or("").to_string();
            
            if !client_headers.is_parsed_header(&key_str) {
                client_headers.other_headers.insert(key_str, value_str);
            }
        }
        
        client_headers
    }
    
    fn is_parsed_header(&self, header: &str) -> bool {
        let parsed_headers = [
            "host", "user-agent", "accept", "accept-encoding",
            "accept-language", "connection", "cache-control",
            "cookie", "authorization", "content-type",
            "content-length", "referer", "origin",
            "range", "if-range", "if-modified-since",
            "if-unmodified-since", "if-none-match", "if-match",
        ];
        
        parsed_headers.contains(&header)
    }
    
    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.other_headers.get(&name.to_lowercase())
    }
    
    // Проверка условных заголовков
    pub fn should_return_304(&self, last_modified: Option<&DateTime<Utc>>, etag: Option<&str>) -> bool {
        // Проверка If-Modified-Since
        if let Some(since) = &self.if_modified_since {
            if let Some(lm) = last_modified {
                if lm <= since {
                    return true;
                }
            }
        }
        
        // Проверка If-None-Match
        if let Some(if_none_match) = &self.if_none_match {
            if let Some(current_etag) = etag {
                // Если есть * или совпадает любой ETag
                if if_none_match.contains(&"*".to_string()) || 
                   if_none_match.iter().any(|et| et == current_etag) {
                    return true;
                }
            }
        }
        
        false
    }
    
    pub fn should_return_412(&self, last_modified: Option<&DateTime<Utc>>, etag: Option<&str>) -> bool {
        // Проверка If-Unmodified-Since
        if let Some(since) = &self.if_unmodified_since {
            if let Some(lm) = last_modified {
                if lm > since {
                    return true;
                }
            }
        }
        
        // Проверка If-Match
        if let Some(if_match) = &self.if_match {
            if let Some(current_etag) = etag {
                // Если нет * и не совпадает ни один ETag
                if !if_match.contains(&"*".to_string()) && 
                   !if_match.iter().any(|et| et == current_etag) {
                    return true;
                }
            } else if !if_match.is_empty() {
                // Если ETag отсутствует, но запрос требует проверки
                return true;
            }
        }
        
        false
    }
    
    // Проверка, можно ли использовать Range
    pub fn can_use_range(&self, last_modified: Option<&DateTime<Utc>>, etag: Option<&str>) -> bool {
        match &self.if_range {
            Some(IfRangeHeader::ETag(if_range_etag)) => {
                // Если If-Range содержит ETag, сравниваем
                etag.map(|e| e == if_range_etag).unwrap_or(false)
            }
            Some(IfRangeHeader::Date(if_range_date)) => {
                // Если If-Range содержит дату, сравниваем с Last-Modified
                last_modified.map(|lm| lm <= if_range_date).unwrap_or(false)
            }
            None => true, // Если If-Range отсутствует, Range всегда валиден
        }
    }
}


use hyper::header::HeaderName;

fn parse_range_header(headers: &HeaderMap) -> Option<RangeHeader> {
    let range_header = headers.get(RANGE)?;
    let range_str = range_header.to_str().ok()?;
    
    let parts: Vec<&str> = range_str.split('=').collect();
    if parts.len() != 2 {
        return None;
    }
    
    let unit = parts[0].trim().to_string();
    let ranges_str = parts[1].trim();
    
    let mut ranges = Vec::new();
    
    for range in ranges_str.split(',') {
        let range = range.trim();
        if range.is_empty() {
            continue;
        }
        
        let bounds: Vec<&str> = range.split('-').collect();
        if bounds.len() != 2 {
            continue;
        }
        
        let start = bounds[0].parse::<u64>().ok();
        let end = bounds[1].parse::<u64>().ok();
        
        ranges.push(RangeSpec { start, end });
    }
    
    if ranges.is_empty() {
        None
    } else {
        Some(RangeHeader { unit, ranges })
    }
}

fn parse_if_range_header(headers: &HeaderMap) -> Option<IfRangeHeader> {
    let if_range = headers.get(IF_RANGE)?;
    let if_range_str = if_range.to_str().ok()?;
    
    // Пробуем парсить как дату
    if let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(if_range_str) {
        return Some(IfRangeHeader::Date(datetime.into()));
    }
    
    // Если не дата, то это ETag (убираем кавычки)
    let etag = if_range_str.trim_matches('"').to_string();
    Some(IfRangeHeader::ETag(etag))
}

fn parse_date_header(headers: &HeaderMap, header_name: HeaderName) -> Option<DateTime<Utc>> {
    headers.get(header_name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| parse_http_date(s))
}
// Парсинг HTTP дат в форматах RFC 7231 (Section 7.1.1.1)
pub fn parse_http_date(date_str: &str) -> Option<DateTime<Utc>> {
    // Убираем лишние пробелы
    let date_str = date_str.trim();
    
    // Пробуем разные форматы HTTP дат
    let formats = [
        // RFC 7231/HTTP-date formats:
        "%a, %d %b %Y %H:%M:%S GMT",  // IMF-fixdate (предпочтительный)
        "%A, %d-%b-%y %H:%M:%S GMT",  // obsolete RFC 850 format
        "%a %b %d %H:%M:%S %Y",       // ANSI C's asctime() format
    ];
    
    for format in &formats {
        if let Ok(dt) = DateTime::parse_from_str(date_str, format) {
            return Some(dt.with_timezone(&Utc));
        }
    }
    
    // Альтернативный метод через ручной парсинг
    parse_http_date_manual(date_str)
}

fn parse_http_date_manual(date_str: &str) -> Option<DateTime<Utc>> {
    let mut parsed = Parsed::new();
    
    // Удаляем "GMT" если присутствует (все HTTP даты в GMT)
    let clean_date = date_str.trim_end_matches(" GMT").trim();
    
    // Пробуем разные комбинации
    let mut try_parse = |format: &str| -> ParseResult<()> {
        let items = StrftimeItems::new(format);
        parsed = Parsed::new();
        chrono::format::parse(&mut parsed, clean_date, items)
    };
    
    // IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
    if try_parse("%a, %d %b %Y %H:%M:%S").is_ok() {
        return parsed.to_datetime().ok().map(|dt| dt.with_timezone(&Utc));
    }
    
    // RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
    if try_parse("%A, %d-%b-%y %H:%M:%S").is_ok() {
        // Для двухзначного года chrono сам обработает переход через 2000
        return parsed.to_datetime().ok().map(|dt| dt.with_timezone(&Utc));
    }
    
    // ANSI C's asctime: Sun Nov  6 08:49:37 1994
    if try_parse("%a %b %e %H:%M:%S %Y").is_ok() || 
       try_parse("%a %b %d %H:%M:%S %Y").is_ok() {
        return parsed.to_datetime().ok().map(|dt| dt.with_timezone(&Utc));
    }
    
    None
}

// Форматирование даты в HTTP формат
pub fn format_http_date(dt: &DateTime<Utc>) -> String {
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn parse_etag_list(headers: &HeaderMap, header_name: HeaderName) -> Option<Vec<String>> {
    let header_value = headers.get(header_name)?;
    let header_str = header_value.to_str().ok()?;
    
    // ETag могут быть разделены запятыми
    let etags: Vec<String> = header_str
        .split(',')
        .map(|etag| etag.trim().trim_matches('"').to_string())
        .filter(|etag| !etag.is_empty())
        .collect();
    
    if etags.is_empty() {
        None
    } else {
        Some(etags)
    }
}

fn get_header_str(headers: &HeaderMap, header_name: HeaderName) -> Option<String> {
    headers.get(header_name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn get_header_u64(headers: &HeaderMap, header_name: HeaderName) -> Option<u64> {
    headers.get(header_name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}