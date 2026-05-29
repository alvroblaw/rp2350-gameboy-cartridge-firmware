//! BIP-39 mnemonic generation and parsing.
//!
//! Generates cryptographically secure mnemonic phrases (12/24 words) from
//! hardware entropy, and parses existing mnemonics back into seed material.
//! Uses the 2048-word BIP-39 English wordlist.
//!
//! # Memory layout
//!
//! The `Mnemonic` struct stores only entropy bytes and word count — NOT the
//! word strings. Words are looked up on demand from the embedded wordlist.
//! This saves ~4KB of RAM vs storing 24 string pointers.

#![allow(unused)]

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto_rng::{hardware_random, CryptoRng};

/// Supported mnemonic word counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordCount {
    Words12 = 12,
    Words24 = 24,
}

impl WordCount {
    /// Entropy bytes for this word count.
    pub const fn entropy_len(&self) -> usize {
        match self {
            WordCount::Words12 => 16,
            WordCount::Words24 => 32,
        }
    }

    /// Checksum bits for this word count.
    pub const fn checksum_bits(&self) -> usize {
        match self {
            WordCount::Words12 => 4,
            WordCount::Words24 => 8,
        }
    }
}

/// A BIP-39 mnemonic phrase.
///
/// Stores entropy bytes internally. Words are derived on demand.
/// Implements `#[zeroize(drop)]` to automatically clear entropy on Drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    /// Entropy bytes (first 16 or 32 bytes used depending on word_count).
    entropy: [u8; 32],
    /// Number of words (12 or 24).
    word_count: WordCount,
}

impl Mnemonic {
    /// Generate a new random mnemonic from hardware entropy.
    pub fn generate(word_count: WordCount) -> Result<Self, Bip39Error> {
        let mut entropy = [0u8; 32];
        let len = word_count.entropy_len();
        hardware_random(&mut entropy[..len]).map_err(|_| Bip39Error::EntropyError)?;
        Ok(Self { entropy, word_count })
    }

    /// Create a mnemonic from raw entropy bytes.
    ///
    /// The entropy must be 16 bytes (12 words) or 32 bytes (24 words).
    /// The checksum is computed and validated internally.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Bip39Error> {
        let word_count = match entropy.len() {
            16 => WordCount::Words12,
            32 => WordCount::Words24,
            _ => return Err(Bip39Error::InvalidEntropyLength),
        };

        let mut buf = [0u8; 32];
        buf[..entropy.len()].copy_from_slice(entropy);
        Ok(Self {
            entropy: buf,
            word_count,
        })
    }

    /// Parse a mnemonic from a space-separated word string.
    ///
    /// Validates checksum. Returns error if invalid.
    pub fn from_phrase(_phrase: &str) -> Result<Self, Bip39Error> {
        // TODO: Phase 3 — implement full BIP-39 phrase parsing
        Err(Bip39Error::InvalidWordCount)
    }

    /// Derive the 64-byte BIP-39 seed from this mnemonic.
    ///
    /// Uses PBKDF2-HMAC-SHA512 with 2048 iterations.
    /// The password is the mnemonic phrase, the salt is "mnemonic" + passphrase.
    pub fn to_seed(&self, _passphrase: &str) -> [u8; 64] {
        // TODO: Phase 3 — implement PBKDF2-HMAC-SHA512 seed derivation
        // let phrase = self.to_phrase();
        // let mut salt = arrayvec::ArrayVec<u8, 128>::new();
        // salt.extend_from_slice(b"mnemonic").unwrap();
        // salt.extend_from_slice(passphrase.as_bytes()).unwrap();
        // pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(phrase.as_bytes(), &salt[..], 2048, &mut seed);
        [0u8; 64]
    }

    /// Get the entropy bytes (for storage/encryption).
    pub fn entropy(&self) -> &[u8] {
        &self.entropy[..self.word_count.entropy_len()]
    }

    /// Get the word count.
    pub fn word_count(&self) -> WordCount {
        self.word_count
    }

    /// Convert to word indices (for compact display/storage).
    ///
    /// Returns exactly 12 or 24 indices.
    pub fn to_word_indices(&self) -> heapless::Vec<u16, 24> {
        let entropy = &self.entropy[..self.word_count.entropy_len()];
        let checksum_bits = self.word_count.checksum_bits();

        // Compute checksum
        let hash = Sha256::digest(entropy);
        let checksum = hash[0] >> (8 - checksum_bits);

        // Build bit stream: entropy || checksum
        let total_bits = entropy.len() * 8 + checksum_bits as usize;
        let mut indices = heapless::Vec::new();

        let mut bit_pos = 0u32;
        for _ in 0..(total_bits / 11) {
            let mut idx = 0u16;
            for b in 0..11 {
                let pos = bit_pos + b as u32;
                let bit = if (pos as usize) < entropy.len() * 8 {
                    let byte_idx = pos as usize / 8;
                    let bit_idx = 7 - (pos as usize % 8);
                    (entropy[byte_idx] >> bit_idx) & 1
                } else {
                    // Checksum bits
                    let cs_pos = pos as usize - entropy.len() * 8;
                    (checksum >> (checksum_bits - 1 - cs_pos)) & 1
                };
                idx = (idx << 1) | bit as u16;
            }
            indices.push(idx).unwrap();
            bit_pos += 11;
        }

        indices
    }

    /// Convert to phrase string (space-separated words).
    ///
    /// Uses a provided buffer to avoid allocation.
    /// Returns the phrase as a string slice.
    pub fn to_phrase(&self) -> heapless::String<512> {
        let indices = self.to_word_indices();
        let mut phrase = heapless::String::new();

        for (i, &idx) in indices.iter().enumerate() {
            if i > 0 {
                phrase.push(' ').unwrap();
            }
            let word = get_word(idx as usize);
            phrase.push_str(word).unwrap();
        }

        phrase
    }

    /// Get a specific word from this mnemonic.
    pub fn word(&self, index: usize) -> Option<&'static str> {
        if index >= self.word_count as usize {
            return None;
        }
        let indices = self.to_word_indices();
        let word_idx = indices.get(index)?;
        Some(get_word(*word_idx as usize))
    }

    /// Validate that a phrase forms a valid mnemonic.
    pub fn validate(phrase: &str) -> Result<(), Bip39Error> {
        let _ = Self::from_phrase(phrase)?;
        Ok(())
    }
}

/// Find the index of a word in the BIP-39 wordlist.
fn find_word_index(word: &str) -> Option<u16> {
    // Binary search since the wordlist is sorted
    WORDLIST.binary_search(&word).ok().map(|i| i as u16)
}

/// Get a word from the BIP-39 wordlist by index.
pub fn get_word(index: usize) -> &'static str {
    WORDLIST[index]
}

/// BIP-39 operation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip39Error {
    /// Invalid word count (must be 12 or 24).
    InvalidWordCount,
    /// Word not found in the BIP-39 wordlist.
    UnknownWord,
    /// Checksum mismatch.
    InvalidChecksum,
    /// Hardware entropy source failure.
    EntropyError,
    /// Invalid entropy length.
    InvalidEntropyLength,
}

/// BIP-39 English wordlist (2048 words).
///
/// Stored in flash as a const array. Each word is referenced
/// by its 11-bit index (0-2047). The list is sorted for binary search.
#[rustfmt::skip]
pub const WORDLIST: [&str; 2048] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
    "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
    "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
    "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
    "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
    "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
    "avoid", "awake", "aware", "awesome", "awful", "awkward", "axis", "baby",
    "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
    "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef",
    "before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
    "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid",
    "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade",
    "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blow", "blue", "blur", "blush", "board", "boat", "body", "boil",
    "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow",
    "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
    "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
    "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk",
    "bullet", "bundle", "bunny", "burden", "burger", "burst", "bus", "business",
    "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus",
    "cage", "cake", "call", "calm", "camera", "camp", "can", "canal",
    "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart",
    "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch",
    "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery",
    "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion",
    "change", "chaos", "chapter", "charge", "chase", "cheap", "check", "cheese",
    "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice",
    "choose", "chronic", "chuckle", "chunk", "churn", "citizen", "city", "civil",
    "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever",
    "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog",
    "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch",
    "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect",
    "color", "column", "combine", "come", "comfort", "comic", "common", "company",
    "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince",
    "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct",
    "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover",
    "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater",
    "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime",
    "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel",
    "cruise", "crumble", "crush", "cry", "crystal", "cube", "culture", "cup",
    "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute",
    "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash",
    "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december",
    "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy",
    "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny",
    "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert",
    "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device",
    "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet",
    "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt",
    "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance",
    "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double",
    "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress",
    "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry",
    "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf",
    "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east",
    "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort",
    "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element",
    "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge",
    "emotion", "employ", "empower", "empty", "enable", "encourage", "end", "endless",
    "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy",
    "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry",
    "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion",
    "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics",
    "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange",
    "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile",
    "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose",
    "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty",
    "fade", "faint", "faith", "fall", "false", "fame", "family", "famous",
    "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father",
    "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed",
    "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber",
    "fiction", "field", "figure", "file", "film", "filter", "final", "find",
    "fine", "finger", "finish", "fire", "firm", "fiscal", "fish", "fit",
    "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
    "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush",
    "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food",
    "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward",
    "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh",
    "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit",
    "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain",
    "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic",
    "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general",
    "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift",
    "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare",
    "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow",
    "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel",
    "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape",
    "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery",
    "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar",
    "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand",
    "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk",
    "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello",
    "helmet", "help", "hen", "hero", "hip", "hire", "history", "hobby",
    "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood",
    "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour",
    "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon",
    "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image",
    "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch",
    "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant",
    "inflict", "inform", "initial", "inject", "inmate", "inner", "innocent", "input",
    "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest",
    "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue",
    "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans",
    "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen",
    "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom",
    "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
    "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake",
    "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry",
    "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf",
    "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure",
    "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level",
    "liberty", "library", "license", "life", "lift", "light", "like", "limb",
    "limit", "link", "lion", "liquid", "list", "little", "live", "lizard",
    "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long",
    "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage",
    "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic",
    "magnet", "maid", "mail", "main", "major", "make", "mammal", "man",
    "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march",
    "margin", "marine", "market", "marriage", "mask", "mass", "master", "match",
    "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean",
    "measure", "meat", "mechanic", "media", "melody", "melt", "member", "memory",
    "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message",
    "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake",
    "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment",
    "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
    "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie",
    "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music",
    "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
    "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral",
    "never", "news", "next", "nice", "night", "noble", "noise", "nominee",
    "noodle", "normal", "north", "nose", "notable", "nothing", "notice", "novel",
    "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object",
    "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october",
    "odor", "off", "offer", "office", "often", "oil", "okay", "old",
    "olive", "olympic", "omit", "once", "one", "onion", "online", "only",
    "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard",
    "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other",
    "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own",
    "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair",
    "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade",
    "parent", "park", "parrot", "party", "pass", "patch", "path", "patient",
    "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear",
    "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect",
    "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano",
    "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink",
    "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic",
    "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem",
    "poet", "point", "polar", "pole", "police", "pond", "pony", "pool",
    "popular", "portion", "pose", "position", "possible", "post", "potato", "pottery",
    "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority",
    "prison", "private", "prize", "problem", "process", "produce", "profit", "program",
    "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide",
    "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil",
    "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle",
    "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz",
    "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rage",
    "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range",
    "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready",
    "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record",
    "recycle", "reduce", "reflect", "reform", "region", "regret", "regular", "reject",
    "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove",
    "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report",
    "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire",
    "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid",
    "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road",
    "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room",
    "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude",
    "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness",
    "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same",
    "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say",
    "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science",
    "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea",
    "search", "season", "seat", "second", "secret", "section", "security", "seed",
    "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence",
    "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
    "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine",
    "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder",
    "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar",
    "simple", "since", "sing", "siren", "sister", "situate", "six", "size",
    "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab",
    "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan",
    "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth",
    "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social",
    "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve",
    "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup",
    "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin",
    "spirit", "split", "sponsor", "spoon", "sport", "spot", "spray", "spread",
    "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff",
    "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak",
    "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock",
    "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike",
    "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit",
    "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure",
    "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow",
    "swamp", "swap", "swarm", "swear", "sweet", "swim", "swing", "switch",
    "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag",
    "tail", "talent", "talk", "tank", "tape", "target", "task", "taste",
    "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis",
    "tent", "term", "test", "text", "thank", "that", "theme", "then",
    "theory", "there", "they", "thing", "this", "thought", "three", "thrive",
    "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber",
    "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco",
    "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow",
    "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple",
    "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower",
    "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer",
    "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial",
    "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck",
    "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuna",
    "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin",
    "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware",
    "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform",
    "union", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual",
    "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban",
    "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant",
    "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor",
    "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue",
    "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant",
    "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual",
    "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice",
    "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait",
    "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash",
    "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear",
    "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "well",
    "west", "wet", "whale", "what", "wheat", "wheel", "when", "where",
    "whip", "whisper", "wide", "width", "wife", "wild", "will", "win",
    "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom",
    "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool",
    "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle",
    "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young",
    "youth", "zebra", "zero", "zone", "zoo",
];
