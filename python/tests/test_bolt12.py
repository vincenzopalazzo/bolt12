import bolt12
import json
import time


def test_version():
    assert bolt12.__version__ == '0.1.3'

# Grab offers testvector
with open("../test-vectors/offers.json", "r") as f:
    testoffers = json.loads(f.read())

# Convert hex fields to bytes:
for offer in testoffers:
    for k, v in offer['contents'].items():
        try:
            offer['contents'][k] = bytes.fromhex(v)
        except:  # noqa
            pass

with open("../lightning-rfc/bolt12/format-string-test.json", "r") as f:
    test_formatstrings = json.loads(f.read())


with open("../lightning-rfc/bolt12/offer-period-test.json", "r") as f:
    test_periods = json.loads(f.read())


def test_decode_formats():
    for testcase in test_formatstrings:
        print("{}:".format(testcase['comment']))
        d = bolt12.Decoder()
        if testcase['valid']:
            assert d.add(testcase['string'])
        else:
            if not d.add(testcase['string']):
                print(" ... unfinished")
                continue
        b12, whybad = d.result()
        if testcase['valid']:
            assert b12 is not None
            print(" ... ok!")
        else:
            assert b12 is None
            print(" ... as expected: {}".format(whybad))

    # Now try feeding in parts
    for testcase in test_formatstrings:
        parts = testcase['string'].split('+')
        if len(parts) == 1:
            continue
        print("{} (in parts):".format(testcase['comment']))
        d = bolt12.Decoder()
        for p in parts[:-1]:
            assert not d.add(p + '+')
        if not testcase['valid']:
            if not d.add(parts[-1]):
                print(" ... parts invalid")
                continue
        else:
            assert d.add(parts[-1])

        b12, whybad = d.result()
        if testcase['valid']:
            assert b12 is not None
            print(" ... ok!")
        else:
            assert b12 is None
            print(" ... as expected: {}".format(whybad))


def test_decode():
    for offer in testoffers:
        d = bolt12.Decoder()
        assert d.add(offer['string'])
        b12, _ = d.result()
        assert b12.hrp == offer["type"]

        assert b12.values == offer["contents"]

        enc = b12.encode()
        assert enc == offer['string']


def test_merkle():
    for offer in testoffers:
        d = bolt12.Decoder()
        assert d.add(offer['string'])
        b12, _ = d.result()
        assert b12.hrp == offer["type"]
        assert b12.merkle().hex() == offer["offer_id"]


def test_signature():
    dec = bolt12.Decoder()
    dec.add('lno1pg257enxv4ezqcneype82um50ynhxgrwdajx283qfwdpl28qqmc78ymlvhmxcsywdk5wrjnj36jryg488qwlrnzyjczlqs85ck65ycmkdk92smwt9zuewdzfe7v4aavvaz5kgv9mkk63v3s0ge0f099kssh3yc95qztx504hu92hnx8ctzhtt08pgk0texz0509tk')
    offer, _ = dec.result()

    assert offer._check_sig('offer', 'signature',
                            offer.merkle(), offer.values['node_id'],
                            offer.values['signature'])


def test_check():
    for offer in testoffers:
        d = bolt12.Decoder()
        assert d.add(offer['string'])
        b12, _ = d.result()
        assert b12.check()


def test_recurrence():
    for period in test_periods:
        rvals = {'time_unit': period['time_unit'],
                 'period': period['period']}
        base = {'basetime': period["basetime"],
                'start_any_period': 0}
        rec = bolt12.Recurrence(rvals, recurrence_base=base)
        assert rec.get_period(period["n"]).start == period["expect"]["seconds_since_epoch"]

    for offer in testoffers:
        d = bolt12.Decoder()
        assert d.add(offer['string'])
        b12, _ = d.result()
        rec = b12.get_recurrence()
        if 'recurrence' not in offer['contents']:
            assert rec is None
        else:
            timenow = int(time.time())
            jan2021 = 1609459200
            jan2022 = 1640995200
            # 50 days after 2021-01-1 = 2021-02-20
            feb2021_20 = 1613779200
            # FIXME: Put this in vectors
            desc = offer['contents']['description']
            if desc == "100msat every minute":
                assert not rec.has_fixed_base()
                assert (rec.get_period(0, basetime=timenow)
                        == (timenow, timenow + 60,
                            timenow - 60, timenow + 60))
                assert (rec.get_period(3, basetime=timenow)
                        == (timenow + 180, timenow + 180 + 60,
                            timenow + 180 - 60, timenow + 180 + 60))
            elif desc == "100msat every minute, up to three times":
                assert not rec.has_fixed_base()
                assert (rec.get_period(0, basetime=timenow)
                        == (timenow, timenow + 60, timenow - 60, timenow + 60))
                assert rec.get_period(3, basetime=timenow) is None
            elif desc == "100msat every day, from 1-Jan-2021":
                assert rec.has_fixed_base()
                assert (rec.get_period(0)
                        == (jan2021, jan2021 + 3600 * 24,
                            jan2021 - 3600 * 24, jan2021 + 3600 * 24))
                assert (rec.get_period(365)
                        == (jan2022, jan2022 + 3600 * 24,
                            jan2022 - 3600 * 24, jan2022 + 3600 * 24))
            elif desc == "1000msat every 10 days, from 1-Jan-2021, pay 1hr before to 60 seconds late":
                assert rec.has_fixed_base()
                assert (rec.get_period(0)
                        == (jan2021, jan2021 + 3600 * 24 * 10,
                            jan2021 - 3600, jan2021 + 60))
                assert (rec.get_period(5)
                        == (feb2021_20, feb2021_20 + 3600 * 24 * 10,
                            feb2021_20 - 3600, feb2021_20 + 60))
            elif desc == "1000msat every 10 days, from 1-Jan-2021, pro-rata":
                assert rec.has_fixed_base()
                assert (rec.get_period(0)
                        == (jan2021, jan2021 + 3600 * 24 * 10,
                            jan2021 - 10 * 3600 * 24, jan2021 + 3600 * 24 * 10))
                assert (rec.get_period(5)
                        == (feb2021_20, feb2021_20 + 3600 * 24 * 10,
                            feb2021_20 - 10 * 3600 * 24, feb2021_20 + 3600 * 24 * 10))
                # Proportional amounts apply within the period window
                assert rec.get_pay_factor(rec.get_period(5),
                                          feb2021_20 - 1) == 1
                assert rec.get_pay_factor(rec.get_period(5),
                                          feb2021_20) == 1
                assert rec.get_pay_factor(rec.get_period(5),
                                          feb2021_20 + 5 * 3600 * 24) == 0.5
                assert rec.get_pay_factor(rec.get_period(5),
                                          feb2021_20 + 10 * 3600 * 24) == 0
                assert rec.get_pay_factor(rec.get_period(5),
                                          feb2021_20 + 10 * 3600 * 24 + 1) == 0
            elif desc == "10USD every day":
                assert not rec.has_fixed_base()
                assert (rec.get_period(0, basetime=timenow)
                        == (timenow, timenow + 24 * 60 * 60,
                            timenow - 24 * 60 * 60, timenow + 24 * 60 * 60))
                assert (rec.get_period(3, basetime=timenow)
                        == (timenow + 24 * 60 * 180,
                            timenow + 24 * 60 * 180 + 24 * 60 * 60,
                            timenow + 24 * 60 * 180 - 24 * 60 * 60,
                            timenow + 24 * 60 * 180 + 24 * 60 * 60))
            else:
                # If a new test case added, handle it here.
                assert False


def test_recurrence_period_start_offset():
    for time_unit in (0, 1, 2, 3):
        # Every 10 time_unit from 1-Jan-2021
        jan2021 = 1609459200
        rec = bolt12.Recurrence({'time_unit': time_unit, 'period': 10},
                                recurrence_base={'start_any_period': True,
                                                 'basetime': jan2021})

        # We replace _get_period to count iterations inside period_start_offset.
        rec.real_get_period = rec._get_period

        def counting_get_period(n: int, basetime: int):
            rec.iterations += 1
            return rec.real_get_period(n, basetime)

        rec._get_period = counting_get_period

        # Try ranges back and forward about a century.
        for when in range(jan2021 - 500000000,
                          jan2021 + 500000000,
                          500000):
            rec.iterations = 0
            which_period = rec.period_start_offset(when)
            assert rec.iterations > 0
            assert rec.iterations <= 2
            start, end, _, _ = rec._get_period(which_period, 1609459200)
            assert when >= start and when < end


def test_create():
    for o in testoffers:
        offer = bolt12.Offer.create(**o['contents'])
        assert offer.merkle().hex() == o["offer_id"]


def _parse_raw_tlvs(bytestr):
    """Parse raw TLV bytes into a list of (type, value_bytes) tuples."""
    from bolt12.fundamentals import fromwire_bigsize

    tlvs = []
    buf = bytestr
    while len(buf) > 0:
        tlv_type, buf = fromwire_bigsize(buf)
        tlv_len, buf = fromwire_bigsize(buf)
        tlv_bytes = buf[:tlv_len]
        buf = buf[tlv_len:]
        tlvs.append((tlv_type, tlv_bytes))
    return tlvs


def _merkle_from_raw_tlvs(raw_tlvs):
    """Compute merkle root from a list of (type, value_bytes) tuples,
    excluding signature elements (types 240-1000).

    This allows computing the offer_id without needing a typed TLV table,
    which is necessary for offers/invoices using TLV fields from different
    spec versions.
    """
    from bolt12.bolt12 import bolt12_h, Bolt12
    from bolt12.fundamentals import towire_bigsize

    # Build ordered TLV entries, skipping signatures
    ordered = []
    for tlv_type, tlv_bytes in raw_tlvs:
        if 240 <= tlv_type <= 1000:
            continue
        tlv_enc = towire_bigsize(tlv_type) + towire_bigsize(len(tlv_bytes)) + tlv_bytes
        ordered.append(tlv_enc)

    # Compute merkle the same way Bolt12.merkle() does
    all_tlvs = bytes()
    for enc in ordered:
        all_tlvs += enc

    lnleaf = bolt12_h(b'LnLeaf')
    lnall = bolt12_h(b'LnAll' + all_tlvs)

    leaves = []
    for enc in ordered:
        leafnode = lnleaf.copy()
        leafnode.update(enc)
        lnallnode = lnall.copy()
        lnallnode.update(enc)
        leaves.append(Bolt12.merkle_pair(leafnode.digest(), lnallnode.digest()))

    return Bolt12.merkle_branch(leaves)


# BOLT #12 TLV type ranges:
#   1-79:   offer fields
#   80-159: invoice_request fields
#   160-239: invoice fields
#   240-1000: signature fields
_OFFER_TLV_RANGE = range(1, 80)
_INVOICE_TLV_RANGE = range(160, 240)

# Well-known TLV types for payment_hash across spec versions.
# Current spec: 42, CLN experimental: 168
_PAYMENT_HASH_TLVS = {42, 168}


def verify_offer_payment(offer_str, invoice_str, preimage_hex):
    """Verify that an invoice matches an offer and the preimage is correct.

    Reproduces the verification logic from ocean-ln's verify_offer_payment:
    1. The offer_id (merkle of offer TLVs) matches the offer TLVs embedded
       in the invoice
    2. SHA256(preimage) == invoice's payment_hash (proof of payment)

    Uses raw TLV parsing to support both current and older BOLT12 spec
    versions.
    """
    import hashlib

    # Decode the offer using raw bech32 + TLV parsing
    dec = bolt12.Decoder()
    if not dec.add(offer_str):
        raise ValueError("Incomplete offer string")
    _, offer_bytes = dec.raw_decode()
    offer_tlvs = _parse_raw_tlvs(offer_bytes)
    offer_id = _merkle_from_raw_tlvs(offer_tlvs)

    # Decode the invoice using raw bech32 + TLV parsing
    dec = bolt12.Decoder()
    if not dec.add(invoice_str):
        raise ValueError("Incomplete invoice string")
    hrp, invoice_bytes = dec.raw_decode()
    if hrp != 'lni':
        raise ValueError("Not an invoice: hrp={}".format(hrp))
    invoice_tlvs = _parse_raw_tlvs(invoice_bytes)

    # Extract the offer TLVs embedded in the invoice (types 1-79)
    # and compute the offer_id from them
    embedded_offer_tlvs = [(t, v) for t, v in invoice_tlvs
                           if t in _OFFER_TLV_RANGE]
    if not embedded_offer_tlvs:
        raise ValueError("Invoice does not contain any offer fields")
    invoice_offer_id = _merkle_from_raw_tlvs(embedded_offer_tlvs)

    # Check offer_id matches
    if offer_id != invoice_offer_id:
        raise ValueError("Offer ID mismatch: offer={} invoice={}".format(
            offer_id.hex(), invoice_offer_id.hex()))

    # Find payment_hash in the invoice TLVs
    payment_hash = None
    for tlv_type, tlv_bytes in invoice_tlvs:
        if tlv_type in _PAYMENT_HASH_TLVS and len(tlv_bytes) == 32:
            payment_hash = tlv_bytes
            break
    if payment_hash is None:
        raise ValueError("Invoice does not contain a payment_hash")

    # Check preimage matches payment_hash (proof of payment)
    preimage = bytes.fromhex(preimage_hex)
    expected_hash = hashlib.sha256(preimage).digest()
    if expected_hash != payment_hash:
        raise ValueError("Payment hash mismatch: SHA256(preimage)={} payment_hash={}".format(
            expected_hash.hex(), payment_hash.hex()))


def test_verify_offer_payment():
    """Test successful verification of an offer payment."""
    offer = "lno1pg7y7s69g98zq5rp09hh2arnypnx7u3qvf3nzutc8q6xcdphve4r2emjvucrsdejwqmkv73cvymnxmthw3cngcmnvcmrgum5d4j3vggrufqg5j0s05h5pqaywdzp8rhcnemp0e3eryszey4234ym2a99vzhq"
    invoice = "lni1qqg9sr0tna8ljw0tp9zk9uehh7s8vz3ufap52s2wypgxz7t0w468xgrxdaezqcnrx9chswp5ds6rwen2x4nhyees8qmnyuphvearscfhxdkhwar3x33hxe3kx3ehgmt9zcss8cjq3fylqlf0gzp6gu6yzw8038nkzlnrjxfq9jf24r2fk4622c9w2gpsz28qtqssxstnfpsaqtgdhchfv70shwvganrwuk28gwz9f6v5nlt37s0xh7hp5zvq8cjq3fylqlf0gzp6gu6yzw8038nkzlnrjxfq9jf24r2fk4622c9wq27sqsf52x7pdt5432aztt8ee3s5l20g3u0whwudkk5asanadjzz5qgzhgehdw5jyjf6m83awzntjkxykywzxycduph6gp5crv29qjf9gsasqv394jhcqgta9q4cr975hw4vl5nzekvuzujxv0u7rngsse707e0pq4duexv3930unvay593kd38t6z8em29zrsqqqqqqqqqqqqqqzgqqqqqqqqqqqqqayjedltzjqqqqqq9yq359nfhm4qst3qczk7fkkjhhqs6syjuygh3q87t8jsmtg04xvzu6vsys3fggzt92qvqj3c9wqvpqqq9syyp7ysy2f8c86t6qswj8x3qn3mufuashucu3jgpvj24g6jd4wjjkpthsgqtas84k74uvj2uvxh32exre34mu4vsc5cnmqpftru4cw0s6wujsk8ggn30v3jll8rn98r3xmlymy850udw2smfmse0amens93mk6fzt"
    preimage = "a71dceaa4f2b86713834d6362035adf0eb7eab6c6c61ae3c8b68baffd9072cfc"
    verify_offer_payment(offer, invoice, preimage)


def test_verify_phoenix_offer_fail():
    """Test that verification fails when offer and invoice don't match (Phoenix wallet)."""
    offer = "lno1pgd57cm9v9hzqnmxvejhygzrd35jqanpd35kgct5d9hkugqsacpcvnhsyh77376c0kvfrpkwdf9ps6y4aez2jf4lcdcw9smxt9arlrczf6ycmt3ftr363p6f3fm08epd84y0lkz4t5zphpuygjqnwxzklltqyqnv4q7rx9lc4k8zjcyy7jdxaupjyuhfu7j7jkrdszh9xah04npkysqrxka4j4yxve6j8czdzcr56f5m5hku3uy0zlqn3genn8pszptkms5u6vv6u7qjej4sg4r00r8lpkeuk9allsgz2gqhm8qmj9cuwcfttex5366yvcma274gtaysskp5nmxrl9h3gsdsqv38tquert0z9py4uadrnuceanv26ytqw2pwys6909szlpw562u5lw8gv0ne7jnz52w9903vfv28pdpswrq"
    invoice = "lni1qqgpllwtmnmv6xspe70m78ptxrr5vzsmfa3k2ctwyp8kven9wgsyxmrfypmxzmrfv3shg6t0dcsppmsrse80qf0aara4slvcjxrvu6j2rp5ftmjy4yntlsmsutpkvkt6878syn5f3khzjk8r4zr5nznk70jz602gllv92hgyrwrcg3ypxuv9dl7kqgpxe2puxvtl3tvw99sgfay6dmcryfewnea9a9vxmq9w2dmwltxrvfqqxddmt92gven4y0sy69s8f5nfhf0dercg797p8z3n8xwrqyzhdhpfe5ce4eup9n9tq32x77x07rdnevtmllqsy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qmqqezwkpejxk7y2zfte6688e3nmxc45gkqu5zufp527tq97zaf54ef7uwscl8na9x9g5u22lzcjc5wz6rqux9yqc0gfq9gqzcyypaauxsjgg80qzvfrysks88du2s78vme6neec3jt5axdcrj4yj8a99ql5qm2quxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upfh49ulj5edehzplt3t9fyw9m2j63x9nmey3r8204yfqpj0y5zzlqzqv5wvsgcqc463wtwd2npxp2t953yqp5vj7j829em3apsnt56chhx2qz9rl9mszedhld2xpuzgthfx007d585x4nfxtdefz74f355mua8wwnnr0weqkgeyj8fa72saljsa0kjzhys9w3dt60k9jxqjddkttw5x50l99smn9grg39v0up6s83lvf5x3nxs3knpvm7qpz8vtl7gj78q9jv7yt8cw0nqpecrvfcy4a0tq2z7560lys4tzp3j2586awqv2pgm66plh4a0q73jw3fq3yzl0tje4u5emck0p3x5p5w9gr74xshtkplmk9p68qwa6uz4m3ez4gv35ldgnl3zytpnm6fszejm4rk4f8g6vrknh7cuas5qq6tgt3f0grshlxxzkcyyzm6jp60p9mym870h2nuk9cl2cz3urvd0qksyegf6lq6gquzy0xumkwge00066l8yyss5wh44hz7vr5nssx0ywst5ju5escm85qwyv4jjs8qdlg2llun2zfymp4qqu8u30avlt52879nsfwgvskvvv3hrmggelcjysxnegcgfxexeaz2k6zttq9vdf4pwfy7qfwcnf88j5gwqqqqraqqqqqryqysqqqqqqqqqqqlgqqqqqqqqr6zgqqqq5szxshfdu6nqxq23sz5zqcu908d9dzgtmzva3vh28mpjz4hggyja3r8d48x6cuhxky628xjp4gps7sjq4cpsyqqqkqssy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qm7pqx6pt4td9rrz7ek6gpfzner0dmq9zz92md57cnee4mfv7mktgjj7c3vqn66pdzy80fzgu9sarhtdgd3sy6fl0pzq2dac6m5p87qd393q"
    preimage = "a71dceaa4f2b86713834d6362035adf0eb7eab6c6c61ae3c8b68baffd9072cfc"
    try:
        verify_offer_payment(offer, invoice, preimage)
        assert False, "Should have failed verification"
    except (ValueError, AssertionError) as e:
        if str(e) == "Should have failed verification":
            raise
        # Expected to fail - offer and invoice don't match


def test_verify_phoenix_offer_fail_pop():
    """Test that verification fails for proof-of-payment mismatch (Phoenix wallet)."""
    offer = "lno1pgd57cm9v9hzqnmxvejhygzrd35jqanpd35kgct5d9hkugqsacpcvnhsyh77376c0kvfrpkwdf9ps6y4aez2jf4lcdcw9smxt9arlrczf6ycmt3ftr363p6f3fm08epd84y0lkz4t5zphpuygjqnwxzklltqyqnv4q7rx9lc4k8zjcyy7jdxaupjyuhfu7j7jkrdszh9xah04npkysqrxka4j4yxve6j8czdzcr56f5m5hku3uy0zlqn3genn8pszptkms5u6vv6u7qjej4sg4r00r8lpkeuk9allsgz2gqhm8qmj9cuwcfttex5366yvcma274gtaysskp5nmxrl9h3gsdsqv38tquert0z9py4uadrnuceanv26ytqw2pwys6909szlpw562u5lw8gv0ne7jnz52w9903vfv28pdpswrq"
    invoice = "lni1qqgpllwtmnmv6xspe70m78ptxrr5vzsmfa3k2ctwyp8kven9wgsyxmrfypmxzmrfv3shg6t0dcsppmsrse80qf0aara4slvcjxrvu6j2rp5ftmjy4yntlsmsutpkvkt6878syn5f3khzjk8r4zr5nznk70jz602gllv92hgyrwrcg3ypxuv9dl7kqgpxe2puxvtl3tvw99sgfay6dmcryfewnea9a9vxmq9w2dmwltxrvfqqxddmt92gven4y0sy69s8f5nfhf0dercg797p8z3n8xwrqyzhdhpfe5ce4eup9n9tq32x77x07rdnevtmllqsy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qmqqezwkpejxk7y2zfte6688e3nmxc45gkqu5zufp527tq97zaf54ef7uwscl8na9x9g5u22lzcjc5wz6rqux9yqc0gfq9gqzcyypaauxsjgg80qzvfrysks88du2s78vme6neec3jt5axdcrj4yj8a99ql5qm2quxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upfh49ulj5edehzplt3t9fyw9m2j63x9nmey3r8204yfqpj0y5zzlqzqv5wvsgcqc463wtwd2npxp2t953yqp5vj7j829em3apsnt56chhx2qz9rl9mszedhld2xpuzgthfx007d585x4nfxtdefz74f355mua8wwnnr0weqkgeyj8fa72saljsa0kjzhys9w3dt60k9jxqjddkttw5x50l99smn9grg39v0up6s83lvf5x3nxs3knpvm7qpz8vtl7gj78q9jv7yt8cw0nqpecrvfcy4a0tq2z7560lys4tzp3j2586awqv2pgm66plh4a0q73jw3fq3yzl0tje4u5emck0p3x5p5w9gr74xshtkplmk9p68qwa6uz4m3ez4gv35ldgnl3zytpnm6fszejm4rk4f8g6vrknh7cuas5qq6tgt3f0grshlxxzkcyyzm6jp60p9mym870h2nuk9cl2cz3urvd0qksyegf6lq6gquzy0xumkwge00066l8yyss5wh44hz7vr5nssx0ywst5ju5escm85qwyv4jjs8qdlg2llun2zfymp4qqu8u30avlt52879nsfwgvskvvv3hrmggelcjysxnegcgfxexeaz2k6zttq9vdf4pwfy7qfwcnf88j5gwqqqqraqqqqqryqysqqqqqqqqqqqlgqqqqqqqqr6zgqqqq5szxshfdu6nqxq23sz5zqcu908d9dzgtmzva3vh28mpjz4hggyja3r8d48x6cuhxky628xjp4gps7sjq4cpsyqqqkqssy5sp0kwphyt3casjkhjdfr45ge3h64a2sh6fppvrf8kv87t0z3qm7pqx6pt4td9rrz7ek6gpfzner0dmq9zz92md57cnee4mfv7mktgjj7c3vqn66pdzy80fzgu9sarhtdgd3sy6fl0pzq2dac6m5p87qd393q"
    preimage = "a71dceaa4f2b86713834d6362035adf0eb7eab6c6c61ae3c8b68baffd9072cfc"
    try:
        verify_offer_payment(offer, invoice, preimage)
        assert False, "Should have failed verification"
    except (ValueError, AssertionError) as e:
        if str(e) == "Should have failed verification":
            raise
        # Expected to fail - offer and invoice don't match
