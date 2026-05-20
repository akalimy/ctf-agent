from analyzer.binary_analyzer import BinaryAnalyzer

a = BinaryAnalyzer('samples/test')
r = a.collect_all()
print('=== CHECKSEC ===')
print(r['checksec'])
print('=== FUNCTIONS ===')
print(r['functions'])