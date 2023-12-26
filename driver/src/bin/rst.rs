pub fn main() {
    let control_path = "/sys/module/elkeid/parameters/control_trace";

    let (mut rs, cancel) = ringslot::RingSlot::new(control_path).unwrap();

    let controler = ringslot::SmithControl::new(control_path).unwrap();

    if let Err(e) = controler.clear_all() {
        println!("{}", e);
    }

    'l1: loop {
        if let Ok(rec) = rs.read_record() {
            // for test only print data_type=59
            if !rec.starts_with(b"59") {
                continue 'l1;
            }
            let rec_collect = rec.split(|c| *c == 0);
            'l2: for each in rec_collect.into_iter() {
                if let Ok(tc) = String::from_utf8(each.to_vec()) {
                    print!("{} ", tc);
                }
            }
            println!("");
        }
    }
}
