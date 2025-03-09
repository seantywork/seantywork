pub mod howareyou;

pub struct Spoken<'world> {
    pub raw: &'world str,
}

pub fn speak(word: &str) -> Box<String>{


    let mut new_string = "".to_owned();

    let wordstr = word.to_string();

    let wordsize = String::from(wordstr.len().to_string().as_str());

    new_string.push_str(&wordstr);

    new_string.push_str(&" : word len is: ".to_owned());

    new_string.push_str(&wordsize);

    let retbox = Box::new(new_string);

    return retbox;

}

impl<'world> Spoken<'world> {

    pub fn insert(&mut self, word: &'world str){


        self.raw = word;

    } 

    pub fn heart_out(self) -> &'world str{
 
        return self.raw;
    
    }

}


